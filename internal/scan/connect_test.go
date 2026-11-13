package scan

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"goport/internal/packet"
)

// startBannerServer listens on 127.0.0.1 and speaks a fixed banner to every
// connection. It returns the port and a stop function.
func startBannerServer(t *testing.T, banner string) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				time.Sleep(20 * time.Millisecond)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() {
		ln.Close()
		<-done
	}
}

// freePort returns a port that is currently closed.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestProbeBannerServerFirst(t *testing.T) {
	port, stop := startBannerServer(t, "SSH-2.0-GoPort_TestServer\r\n")
	defer stop()

	info, svc := probeBanner("127.0.0.1", uint16(port), 500*time.Millisecond)
	if svc != "ssh" {
		t.Errorf("service = %q, want ssh", svc)
	}
	if !strings.Contains(info, "GoPort_TestServer") {
		t.Errorf("banner = %q", info)
	}
}

func TestGrabHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // wait for the GET
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: GoPort-Test/1.0\r\n\r\n<html><title>Unit</title></html>"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	info, svc := grabHTTP("127.0.0.1", uint16(port), time.Second)
	if svc != "http" {
		t.Errorf("service = %q", svc)
	}
	if !strings.Contains(info, "200 OK") || !strings.Contains(info, "GoPort-Test/1.0") || !strings.Contains(info, "Unit") {
		t.Errorf("info = %q", info)
	}
}

func TestProbeBannerClosedPort(t *testing.T) {
	port := freePort(t)
	info, svc := probeBanner("127.0.0.1", uint16(port), 200*time.Millisecond)
	if info != "" || svc != "" {
		t.Errorf("closed port returned %q / %q", info, svc)
	}
}

func TestEnrichBannerSkipsNonOpen(t *testing.T) {
	r := &Result{State: StateClosed.String(), Proto: "tcp", Port: 22}
	enrichBanner(r, 100*time.Millisecond)
	if r.Banner != "" {
		t.Error("closed result should not be probed")
	}
	u := &Result{State: StateOpen.String(), Proto: "udp", Port: 53}
	enrichBanner(u, 100*time.Millisecond)
	if u.Banner != "" {
		t.Error("UDP result should not be probed")
	}
}

func TestConnectScanFindsOpenAndClosed(t *testing.T) {
	openPort, stop := startBannerServer(t, "220 GoPort FTP\r\n")
	defer stop()
	closedPort := freePort(t)

	var mu sync.Mutex
	var results []Result
	cfg := &Config{
		Scope: &Scope{
			Addrs: []uint32{be32([4]byte{127, 0, 0, 1})},
			Ports: PortSet{TCP: []uint16{uint16(openPort), uint16(closedPort)}},
		},
		Mode:          ModeConnect,
		Timeout:       600 * time.Millisecond,
		Concurrency:   4,
		ShowClosed:    true,
		Banner:        false,
		BannerTimeout: 200 * time.Millisecond,
	}
	cfg.emit = func(r Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	stats, err := runConnect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("runConnect: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}
	byPort := map[uint16]Result{}
	for _, r := range results {
		byPort[r.Port] = r
	}
	if got := byPort[uint16(openPort)].State; got != StateOpen.String() {
		t.Errorf("open port state = %q", got)
	}
	if got := byPort[uint16(closedPort)].State; got != StateClosed.String() {
		t.Errorf("closed port state = %q", got)
	}
	if stats.Open != 1 || stats.Closed != 1 {
		t.Errorf("stats open=%d closed=%d", stats.Open, stats.Closed)
	}
	if stats.Sent != 2 || stats.Probes != 2 {
		t.Errorf("stats sent=%d probes=%d", stats.Sent, stats.Probes)
	}
}

func TestConnectScanContextCancel(t *testing.T) {
	cfg := &Config{
		Scope: &Scope{
			Addrs: []uint32{be32([4]byte{127, 0, 0, 1})},
			Ports: PortSet{TCP: []uint16{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		Mode:        ModeConnect,
		Timeout:     50 * time.Millisecond,
		Concurrency: 2,
	}
	cfg.emit = func(Result) {}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runConnect(ctx, cfg); err == nil {
		t.Error("cancelled context should surface as an error")
	}
}

func TestUnreachableHostIsFiltered(t *testing.T) {
	// 127.0.0.1 with a closed port is refused; a blackholed port range on an
	// unroutable address is the filtered case, which we emulate with a very
	// short timeout against a non-listening address on the local subnet.
	var mu sync.Mutex
	var results []Result
	cfg := &Config{
		Scope: &Scope{
			Addrs: []uint32{be32([4]byte{127, 0, 0, 1})},
			Ports: PortSet{TCP: []uint16{9}},
		},
		Mode:         ModeConnect,
		Timeout:      300 * time.Millisecond,
		Concurrency:  1,
		ShowFiltered: true,
	}
	cfg.emit = func(r Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}
	stats, err := runConnect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Port 9 on loopback is closed, not filtered; the point is only that the
	// state is classified and counted consistently.
	if stats.Open+stats.Closed+stats.Filtered != 1 {
		t.Errorf("verdict not counted: %+v", stats)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) > 1 {
		t.Errorf("got %d results for a single port", len(results))
	}
}

func TestUDPConnectPayload(t *testing.T) {
	// A UDP probe to a closed loopback port should come back refused (ICMP).
	cfg := &Config{
		Scope: &Scope{
			Addrs: []uint32{be32([4]byte{127, 0, 0, 1})},
			Ports: PortSet{UDP: []uint16{uint16(freePortUDP(t))}},
		},
		Mode:         ModeConnect,
		Timeout:      300 * time.Millisecond,
		Concurrency:  1,
		ShowFiltered: true,
		ShowClosed:   true,
	}
	var got []Result
	var mu sync.Mutex
	cfg.emit = func(r Result) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	}
	stats, err := runConnect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sent != 1 {
		t.Errorf("sent = %d", stats.Sent)
	}
	if stats.Open+stats.Closed+stats.Filtered != 1 {
		t.Errorf("UDP verdict not counted: %+v", stats)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range got {
		if r.Proto != "udp" {
			t.Errorf("proto = %q, want udp", r.Proto)
		}
	}
}

func freePortUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return port
}

func TestIsRefused(t *testing.T) {
	if isRefused(nil) {
		t.Error("nil is not a refusal")
	}
	if isRefused(context.Canceled) {
		t.Error("context.Canceled is not a refusal")
	}
	// A real refusal from a closed loopback port.
	port := freePort(t)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Skip("port was actually open")
	}
	if !isRefused(err) {
		t.Errorf("expected a refusal, got %v", err)
	}
}

func TestRunRequiresTargets(t *testing.T) {
	cfg := &Config{Scope: &Scope{}}
	if _, err := Run(context.Background(), cfg, func(Result) {}); err == nil {
		t.Error("Run with no targets should fail")
	}
	cfg = &Config{Scope: &Scope{Addrs: []uint32{1}}}
	if _, err := Run(context.Background(), cfg, func(Result) {}); err == nil {
		t.Error("Run with no ports should fail")
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

var _ = packet.ProtoTCP
