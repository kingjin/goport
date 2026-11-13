package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"goport/internal/packet"
)

// runConnect performs a scan with ordinary sockets: no Npcap, no administrator
// rights, and per-connection state. Slower than the SYN engine but it works
// where raw frames cannot be injected.
func runConnect(ctx context.Context, cfg *Config) (Stats, error) {
	cnt := &counters{}
	cnt.probes.Store(uint64(len(cfg.Scope.Addrs)) * uint64(cfg.Scope.Ports.Total()))
	cnt.beginSend()

	gen := newPairGen(cfg.Scope.Addrs, cfg.Scope.Ports, cfg.Shuffle)
	work := make(chan probeReq, 4096)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range work {
				connectOne(ctx, cfg, cnt, r)
			}
		}()
	}

	go func() {
		defer close(work)
		for {
			dst, port, proto, ok := gen.next()
			if !ok {
				return
			}
			select {
			case work <- probeReq{dst: dst, port: port, proto: proto}:
			case <-ctx.Done():
				return
			}
		}
	}()

	stopProgress := make(chan struct{})
	if cfg.Progress != nil {
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-t.C:
					cfg.Progress(cnt.snapshot(cfg.startedAt, len(cfg.Scope.Addrs), 0, 0))
				}
			}
		}()
	}

	wg.Wait()
	close(stopProgress)
	cnt.endSend()
	return cnt.snapshot(cfg.startedAt, len(cfg.Scope.Addrs), 0, 0), ctx.Err()
}

// connectOne probes a single port with connect() and reports the verdict.
func connectOne(ctx context.Context, cfg *Config, cnt *counters, r probeReq) {
	host := U32String(r.dst)
	addr := net.JoinHostPort(host, strconv.Itoa(int(r.port)))
	start := time.Now()

	if r.proto == packet.ProtoUDP {
		cnt.sent.Add(1)
		cnt.done.Add(1)
		report := func(state State, svc string) {
			switch state {
			case StateOpen:
				cnt.open.Add(1)
			case StateClosed:
				cnt.closed.Add(1)
			default:
				cnt.filtered.Add(1)
			}
			if state == StateOpen || (state == StateClosed && cfg.ShowClosed) || (state != StateOpen && state != StateClosed && cfg.ShowFiltered) {
				cfg.emit(Result{
					Host:    host,
					Port:    r.port,
					Proto:   "udp",
					State:   state.String(),
					Service: svc,
					RTT:     time.Since(start),
				})
			}
		}
		conn, err := net.Dial("udp", addr)
		if err != nil {
			report(StateFiltered, ServiceName(r.port))
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
		if _, err := conn.Write(udpPayload(r.port)); err != nil {
			report(StateFiltered, ServiceName(r.port))
			return
		}
		buf := make([]byte, 2048)
		if _, err := conn.Read(buf); err != nil {
			if isRefused(err) {
				report(StateClosed, ServiceName(r.port))
				return
			}
			report(StateOpenFiltered, ServiceName(r.port))
			return
		}
		report(StateOpen, ServiceName(r.port))
		return
	}

	d := net.Dialer{Timeout: cfg.Timeout}
	cnt.sent.Add(1)
	conn, err := d.DialContext(ctx, "tcp", addr)
	cnt.done.Add(1)
	rtt := time.Since(start)
	if err == nil {
		conn.Close()
		cnt.open.Add(1)
		cnt.received.Add(1)
		cfg.emit(Result{
			Host:    host,
			Port:    r.port,
			Proto:   "tcp",
			State:   StateOpen.String(),
			Service: ServiceName(r.port),
			RTT:     rtt,
		})
		return
	}
	switch {
	case isRefused(err):
		cnt.closed.Add(1)
		cnt.received.Add(1)
		if cfg.ShowClosed {
			cfg.emit(Result{Host: host, Port: r.port, Proto: "tcp", State: StateClosed.String(),
				Service: ServiceName(r.port), RTT: rtt})
		}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		cnt.filtered.Add(1)
	default:
		cnt.filtered.Add(1)
		if cfg.ShowFiltered {
			cfg.emit(Result{Host: host, Port: r.port, Proto: "tcp", State: StateFiltered.String(),
				Service: ServiceName(r.port), RTT: rtt})
		}
	}
}

// isRefused detects "connection refused" across the Windows error surface.
func isRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return true
		}
	}
	// Windows surfaces WSAECONNREFUSED (10061) sometimes wrapped in text only.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "actively refused") || strings.Contains(msg, "积极拒绝")
}
