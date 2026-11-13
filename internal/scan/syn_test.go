package scan

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"goport/internal/netinfo"
	"goport/internal/packet"
)

var (
	ourIP  = packet.IPv4{10, 0, 0, 1}
	ourMAC = packet.MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	tgtIP  = packet.IPv4{10, 0, 0, 9}
	tgtMAC = packet.MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

// tcpFrame builds an Ethernet/IPv4/TCP frame from the target back to us.
func tcpFrame(srcIP, dstIP packet.IPv4, sport, dport uint16, seq, ack uint32, flags uint8) []byte {
	frame := make([]byte, 14+20+20)
	copy(frame[0:6], ourMAC[:])
	copy(frame[6:12], tgtMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], packet.EthTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = packet.ProtoTCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], packet.Checksum(ip[:20]))
	tcp := frame[34:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	return frame
}

// udpFrame builds a UDP datagram from the target back to us.
func udpFrame(srcIP, dstIP packet.IPv4, sport, dport uint16) []byte {
	frame := make([]byte, 14+20+8+4)
	copy(frame[0:6], ourMAC[:])
	copy(frame[6:12], tgtMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], packet.EthTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 32)
	ip[8] = 64
	ip[9] = packet.ProtoUDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], packet.Checksum(ip[:20]))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(udp[8:], "pong")
	return frame
}

// icmpUnreach builds an ICMP port-unreachable quoting our UDP probe.
func icmpUnreach(targetIP, ourIP packet.IPv4, targetPort, ourPort uint16) []byte {
	orig := make([]byte, 20+8)
	orig[0] = 0x45
	binary.BigEndian.PutUint16(orig[2:4], 28)
	orig[8] = 64
	orig[9] = packet.ProtoUDP
	copy(orig[12:16], ourIP[:])
	copy(orig[16:20], targetIP[:])
	binary.BigEndian.PutUint16(orig[10:12], packet.Checksum(orig[:20]))
	binary.BigEndian.PutUint16(orig[20:22], ourPort)
	binary.BigEndian.PutUint16(orig[22:24], targetPort)

	frame := make([]byte, 14+20+8+len(orig))
	copy(frame[0:6], ourMAC[:])
	copy(frame[6:12], tgtMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], packet.EthTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(orig)))
	ip[8] = 64
	ip[9] = packet.ProtoICMP
	copy(ip[12:16], targetIP[:])
	copy(ip[16:20], ourIP[:])
	binary.BigEndian.PutUint16(ip[10:12], packet.Checksum(ip[:20]))
	icmpMsg := frame[34:]
	icmpMsg[0], icmpMsg[1] = 3, 3
	copy(icmpMsg[8:], orig)
	return frame
}

// harness collects results emitted by a scanner under test.
type harness struct {
	s       *synScanner
	mu      sync.Mutex
	results []Result
}

func newHarness(t *testing.T, showClosed, showFiltered bool) *harness {
	t.Helper()
	h := &harness{}
	cfg := &Config{
		Scope:        &Scope{Ports: PortSet{TCP: []uint16{80}, UDP: []uint16{161}}},
		ShowClosed:   showClosed,
		ShowFiltered: showFiltered,
		link:         packet.LinkEthernet,
		srcIP:        ourIP,
		srcMAC:       ourMAC,
		Timeout:      40 * time.Millisecond,
		Retries:      2,
	}
	cfg.emit = func(r Result) {
		h.mu.Lock()
		h.results = append(h.results, r)
		h.mu.Unlock()
	}
	h.s = &synScanner{
		cfg:     cfg,
		builder: packet.NewBuilder(packet.LinkEthernet),
		link:    packet.LinkEthernet,
		srcIP:   ourIP,
		srcMAC:  ourMAC,
		table:   &probeTable{},
		cnt:     &counters{},
		macs:    map[uint32]packet.MAC{tgtIP.Uint32(): tgtMAC},
	}
	return h
}

// TestFrameBufSizeCoversAllPayloads guards the crash where a long UDP probe
// (SIP OPTIONS, SNMP) overflowed a fixed 128-byte frame buffer.
func TestFrameBufSizeCoversAllPayloads(t *testing.T) {
	h := newHarness(t, true, true)
	h.s.cfg.Scope.Ports = PortSet{TCP: []uint16{80}, UDP: []uint16{53, 161, 1900, 5060, 623}}
	buf := make([]byte, h.s.frameBufSize())
	if len(buf) < 42+len(udpPayload(5060)) {
		t.Fatalf("frame buffer %d bytes is smaller than the SIP probe", len(buf))
	}
	for _, p := range h.s.cfg.Scope.Ports.UDP {
		payload := udpPayload(p)
		if n := h.s.builder.BuildUDP(buf, tgtMAC, ourMAC, ourIP, tgtIP, 40000, p, payload); n == 0 {
			t.Errorf("UDP port %d (payload %d) does not fit in %d bytes", p, len(payload), len(buf))
		}
	}
	// TCP always fits in the same buffer.
	if n := h.s.builder.BuildTCPSYN(buf, tgtMAC, ourMAC, ourIP, tgtIP, 40000, 80, 1); n == 0 {
		t.Error("TCP SYN does not fit in the frame buffer")
	}
}

func (h *harness) snapshot() []Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Result(nil), h.results...)
}

// addProbe registers an in-flight TCP probe with a known ISN.
func (h *harness) addProbe(t *testing.T, dport, sport uint16, seq uint32) *probe {
	t.Helper()
	p := &probe{
		key:   makeKey(tgtIP.Uint32(), dport, sport),
		dst:   tgtIP.Uint32(),
		dport: dport,
		sport: sport,
		seq:   seq,
		proto: packet.ProtoTCP,
		echo:  time.Now().Add(-time.Millisecond).UnixNano(),
	}
	h.s.table.insert(p)
	return p
}

func TestHandleFrameSYNACKIsOpen(t *testing.T) {
	h := newHarness(t, true, true)
	h.addProbe(t, 80, 40000, 0x11223344)
	// SYN-ACK must acknowledge our ISN+1.
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 0x9999, 0x11223345, packet.FlagSYN|packet.FlagACK))

	res := h.snapshot()
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	r := res[0]
	if r.State != StateOpen.String() || r.Port != 80 || r.Proto != "tcp" || r.Host != "10.0.0.9" {
		t.Errorf("unexpected result %+v", r)
	}
	if r.Service != "http" {
		t.Errorf("service = %q, want http", r.Service)
	}
	if h.s.table.size() != 0 {
		t.Errorf("probe should be removed, table size = %d", h.s.table.size())
	}
}

func TestHandleFrameSYNACKWrongAckIgnored(t *testing.T) {
	h := newHarness(t, true, true)
	h.addProbe(t, 80, 40000, 0x11223344)
	// Wrong acknowledgement: unrelated traffic, must not be reported.
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 0x9999, 0xdeadbeef, packet.FlagSYN|packet.FlagACK))
	if n := len(h.snapshot()); n != 0 {
		t.Fatalf("got %d results, want 0", n)
	}
	if h.s.table.size() != 1 {
		t.Errorf("probe should stay in flight, table size = %d", h.s.table.size())
	}
}

func TestHandleFrameRSTIsClosed(t *testing.T) {
	h := newHarness(t, true, true)
	h.addProbe(t, 80, 40000, 0x11223344)
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 0, 0x11223345, packet.FlagRST|packet.FlagACK))
	res := h.snapshot()
	if len(res) != 1 || res[0].State != StateClosed.String() {
		t.Fatalf("got %+v, want one closed result", res)
	}
}

func TestHandleFrameRSTIsHiddenWithoutShowClosed(t *testing.T) {
	h := newHarness(t, false, false)
	h.addProbe(t, 80, 40000, 0x11223344)
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 0, 0x11223345, packet.FlagRST|packet.FlagACK))
	if n := len(h.snapshot()); n != 0 {
		t.Fatalf("closed port should be silent by default, got %d results", n)
	}
	if h.s.cnt.closed.Load() != 1 {
		t.Errorf("closed counter = %d, want 1", h.s.cnt.closed.Load())
	}
}

func TestHandleFrameUDPReplyIsOpen(t *testing.T) {
	h := newHarness(t, true, true)
	p := &probe{
		key:   makeKey(tgtIP.Uint32(), 161, 40000),
		dst:   tgtIP.Uint32(),
		dport: 161,
		sport: 40000,
		proto: packet.ProtoUDP,
		echo:  time.Now().UnixNano(),
	}
	h.s.table.insert(p)
	h.s.handleFrame(udpFrame(tgtIP, ourIP, 161, 40000))
	res := h.snapshot()
	if len(res) != 1 || res[0].State != StateOpen.String() || res[0].Proto != "udp" {
		t.Fatalf("got %+v", res)
	}
}

func TestHandleFrameICMPUnreachableIsClosed(t *testing.T) {
	h := newHarness(t, true, true)
	p := &probe{
		key:   makeKey(tgtIP.Uint32(), 161, 40000),
		dst:   tgtIP.Uint32(),
		dport: 161,
		sport: 40000,
		proto: packet.ProtoUDP,
		echo:  time.Now().UnixNano(),
	}
	h.s.table.insert(p)
	h.s.handleFrame(icmpUnreach(tgtIP, ourIP, 161, 40000))
	res := h.snapshot()
	if len(res) != 1 || res[0].State != StateClosed.String() {
		t.Fatalf("got %+v, want closed", res)
	}
}

func TestHandleFrameIgnoresUnrelatedTraffic(t *testing.T) {
	h := newHarness(t, true, true)
	h.addProbe(t, 80, 40000, 0x1111)
	// a) reply for a different source port
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40001, 1, 0x1112, packet.FlagSYN|packet.FlagACK))
	// b) reply for a different destination IP
	other := packet.IPv4{10, 0, 0, 2}
	h.s.handleFrame(tcpFrame(tgtIP, other, 80, 40000, 1, 0x1112, packet.FlagSYN|packet.FlagACK))
	// c) reply to a source port outside our probe range
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 1000, 1, 0x1112, packet.FlagSYN|packet.FlagACK))
	// d) plain data packet (no SYN, no RST)
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 1, 0x1112, packet.FlagACK|packet.FlagPSH))
	// e) truncated frame
	h.s.handleFrame(tcpFrame(tgtIP, ourIP, 80, 40000, 1, 0x1112, packet.FlagSYN|packet.FlagACK)[:20])

	if n := len(h.snapshot()); n != 0 {
		t.Fatalf("got %d results, want 0", n)
	}
	if h.s.table.size() != 1 {
		t.Errorf("original probe should still be in flight")
	}
}

func TestFinishOnlyOnce(t *testing.T) {
	h := newHarness(t, true, true)
	p := h.addProbe(t, 80, 40000, 0x11223344)
	h.s.finish(p, pOpen)
	h.s.finish(p, pClosed) // second verdict must be ignored
	if h.s.cnt.open.Load() != 1 || h.s.cnt.closed.Load() != 0 {
		t.Errorf("open=%d closed=%d, want 1/0", h.s.cnt.open.Load(), h.s.cnt.closed.Load())
	}
	if n := len(h.snapshot()); n != 1 {
		t.Errorf("emitted %d results, want 1", n)
	}
}

func TestProbeTable(t *testing.T) {
	tb := &probeTable{}
	p1 := &probe{key: makeKey(1, 2, 3)}
	if old := tb.insert(p1); old != nil {
		t.Fatal("first insert should not displace anything")
	}
	if !tb.has(p1.key) || tb.size() != 1 {
		t.Fatal("probe not stored")
	}
	// Re-inserting the same key returns the old probe and keeps the count at 1.
	p2 := &probe{key: makeKey(1, 2, 3)}
	if old := tb.insert(p2); old != p1 {
		t.Error("insert should return the displaced probe")
	}
	if tb.size() != 1 {
		t.Errorf("size = %d, want 1", tb.size())
	}
	if got := tb.take(p2.key); got != p2 {
		t.Error("take returned the wrong probe")
	}
	if tb.has(p2.key) || tb.size() != 0 {
		t.Error("probe should be gone after take")
	}
	if tb.take(p2.key) != nil {
		t.Error("take on empty table should return nil")
	}
}

func TestMakeKeyIsStable(t *testing.T) {
	a := makeKey(0x0a000001, 80, 40000)
	b := makeKey(0x0a000001, 80, 40000)
	if a != b {
		t.Error("makeKey must be deterministic")
	}
	if makeKey(1, 2, 3) == makeKey(3, 2, 1) {
		t.Error("makeKey must distinguish dport from sport")
	}
	if makeKey(0x0a000001, 80, 40000) == makeKey(0x0a000002, 80, 40000) {
		t.Error("makeKey must include the host")
	}
}

func TestPairGenCoversEveryPair(t *testing.T) {
	hosts := []uint32{0x0a000001, 0x0a000002, 0x0a000003}
	ports := PortSet{TCP: []uint16{80, 443, 8080}, UDP: []uint16{53, 161}}
	for _, shuffle := range []bool{false, true} {
		g := newPairGen(hosts, ports, shuffle)
		seen := map[string]bool{}
		for {
			h, p, proto, ok := g.next()
			if !ok {
				break
			}
			key := fmt.Sprintf("%d/%d/%d", h, p, proto)
			if seen[key] {
				t.Fatalf("shuffle=%v: duplicate pair %s", shuffle, key)
			}
			seen[key] = true
		}
		if want := len(hosts) * ports.Total(); len(seen) != want {
			t.Errorf("shuffle=%v: covered %d pairs, want %d", shuffle, len(seen), want)
		}
	}
}

func TestPairGenPortRotationVariesPerHost(t *testing.T) {
	hosts := []uint32{0x0a000001, 0x0a000002}
	ports := PortSet{TCP: make([]uint16, 0, 64)}
	for i := 0; i < 64; i++ {
		ports.TCP = append(ports.TCP, uint16(1000+i))
	}
	g := newPairGen(hosts, ports, false)
	firstPort := map[uint32]uint16{}
	for {
		h, p, _, ok := g.next()
		if !ok {
			break
		}
		if _, seen := firstPort[h]; !seen {
			firstPort[h] = p
		}
	}
	if firstPort[hosts[0]] == firstPort[hosts[1]] {
		t.Errorf("both hosts start at port %d; rotation should differ", firstPort[hosts[0]])
	}
}

func TestPairGenEmpty(t *testing.T) {
	g := newPairGen(nil, PortSet{TCP: []uint16{80}}, false)
	if _, _, _, ok := g.next(); ok {
		t.Error("empty host list should yield nothing")
	}
	g = newPairGen([]uint32{1}, PortSet{}, false)
	if _, _, _, ok := g.next(); ok {
		t.Error("empty port list should yield nothing")
	}
}

func TestLimiterRespectsRate(t *testing.T) {
	l := newLimiter(1000) // 1000 pps, burst of 20
	taken := 0
	for i := 0; i < 100; i++ {
		if l.tryTake() {
			taken++
		}
	}
	if taken == 0 || taken > 30 {
		t.Errorf("initial burst allowed %d takes, want 1..30", taken)
	}
	// After refilling for 50ms we should be able to take ~50 more.
	time.Sleep(50 * time.Millisecond)
	if !l.tryTake() {
		t.Error("limiter should refill after sleeping")
	}
	if d := l.sleepFor(); d <= 0 || d > 5*time.Millisecond {
		t.Errorf("sleepFor = %v, want a small positive duration", d)
	}
}

func TestRetransIntervalBackoff(t *testing.T) {
	h := newHarness(t, true, true)
	h.s.cfg.Timeout = 100 * time.Millisecond
	base := h.s.retransInterval(0)
	if base != 100*time.Millisecond {
		t.Errorf("first interval = %v", base)
	}
	if got := h.s.retransInterval(1); got != 200*time.Millisecond {
		t.Errorf("second interval = %v, want 200ms", got)
	}
	// capped at 4x the base
	if got := h.s.retransInterval(5); got != 400*time.Millisecond {
		t.Errorf("capped interval = %v, want 400ms", got)
	}
}

func TestDispatchSkipsHostsWithoutMAC(t *testing.T) {
	h := newHarness(t, true, true)
	buf := make([]byte, 96)
	heap := &probeHeap{}
	unknown := uint32(0x0a000063)
	h.s.dispatch(unknown, 80, packet.ProtoTCP, buf, heap)
	if len(*heap) != 0 {
		t.Error("no probe should be queued for a host without a MAC")
	}
	if h.s.cnt.done.Load() != 1 {
		t.Errorf("done = %d, want 1", h.s.cnt.done.Load())
	}
}

func TestStatsSnapshot(t *testing.T) {
	c := &counters{}
	c.sent.Store(100)
	c.open.Store(3)
	c.probes.Store(200)
	c.done.Store(100)
	s := c.snapshot(time.Now().Add(-time.Second), 5, 1, 0)
	if s.Sent != 100 || s.Open != 3 || s.Hosts != 5 || s.HostsDead != 1 {
		t.Errorf("snapshot = %+v", s)
	}
	if p := s.Progress(); p < 45 || p > 55 {
		t.Errorf("Progress = %.1f, want ~50", p)
	}
	if s.PPS <= 0 {
		t.Errorf("PPS = %.1f", s.PPS)
	}
}

func TestUDPProbePayloads(t *testing.T) {
	if len(udpPayload(53)) == 0 || len(udpPayload(161)) == 0 || len(udpPayload(1900)) == 0 {
		t.Error("well-known UDP ports should carry a probe payload")
	}
	if len(udpPayload(12345)) != 0 {
		t.Error("unknown UDP ports should send an empty datagram")
	}
	// DNS payload structure: 12-byte header + question
	dns := udpPayload(53)
	if len(dns) < 12 || binary.BigEndian.Uint16(dns[4:6]) != 1 {
		t.Error("DNS probe should ask exactly one question")
	}
	if binary.BigEndian.Uint16(dns[2:4]) != 0x0100 {
		t.Error("DNS probe should set the recursion-desired flag")
	}
	// SNMP payload must be a well-formed ASN.1 SEQUENCE
	snmp := udpPayload(161)
	if snmp[0] != 0x30 || int(snmp[1]) != len(snmp)-2 {
		t.Errorf("SNMP probe length mismatch: tag=%#x len=%d total=%d", snmp[0], snmp[1], len(snmp))
	}
}

func TestHandleFrameConcurrentSafety(t *testing.T) {
	h := newHarness(t, true, true)
	const n = 200
	for i := 0; i < n; i++ {
		h.addProbe(t, uint16(1000+i), uint16(40000+i), uint32(i)*7+1)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				dport := uint16(1000 + i)
				sport := uint16(40000 + i)
				// Every reply is delivered eight times: only one may win.
				h.s.handleFrame(tcpFrame(tgtIP, ourIP, dport, sport, 0x9999, uint32(i)*7+2, packet.FlagSYN|packet.FlagACK))
			}
		}()
	}
	wg.Wait()

	res := h.snapshot()
	if len(res) != n {
		t.Fatalf("got %d results, want %d (duplicates must be suppressed)", len(res), n)
	}
	seen := make(map[uint16]bool, n)
	for _, r := range res {
		if seen[r.Port] {
			t.Fatalf("port %d reported twice", r.Port)
		}
		seen[r.Port] = true
	}
	if h.s.table.size() != 0 {
		t.Errorf("table should be empty, size = %d", h.s.table.size())
	}
	if got := h.s.cnt.open.Load(); got != n {
		t.Errorf("open counter = %d, want %d", got, n)
	}
}

func TestArpSeedFiltersJunk(t *testing.T) {
	seed := arpSeed()
	for ip, mac := range seed {
		if !usableMAC(mac) {
			t.Fatalf("arpSeed kept an unusable MAC %v for %s", mac, U32String(ip))
		}
	}
}

func TestIsLoopbackTarget(t *testing.T) {
	if !netinfo.IsLoopbackTarget(netinfo.U32ToAddr(0x7f000001)) {
		t.Error("127.0.0.1 should be loopback")
	}
	if netinfo.IsLoopbackTarget(netinfo.U32ToAddr(0x0a000001)) {
		t.Error("10.0.0.1 is not loopback")
	}
}
