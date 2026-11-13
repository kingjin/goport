package scan

import (
	"container/heap"
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"goport/internal/npcap"
	"goport/internal/packet"
)

// Source ports used for SYN probes. Replies are matched on the full 4-tuple, so
// this pool only needs to be much larger than the number of probes in flight.
const (
	sportLow  = 20000
	sportHigh = 65535
	sportSpan = sportHigh - sportLow + 1
)

// Internal probe states; they map onto State when a result is reported.
const (
	pPending uint32 = iota
	pOpen
	pClosed
	pFiltered
	pOpenFiltered
)

// probe is one in-flight SYN or UDP probe.
type probe struct {
	key     uint64
	dst     uint32
	dport   uint16
	sport   uint16
	seq     uint32
	proto   uint8
	retries uint8
	due     int64 // unix nanos of the next retransmit/expiry
	echo    int64 // unix nanos of the last transmit, for RTT
	state   atomic.Uint32
}

// probeReq is one unit of work produced by the generator.
type probeReq struct {
	dst   uint32
	port  uint16
	proto uint8
}

func makeKey(dst uint32, dport, sport uint16) uint64 {
	return uint64(dst)<<32 | uint64(dport)<<16 | uint64(sport)
}

// ---- probe table -------------------------------------------------------

const probeShards = 64

type probeShard struct {
	mu sync.Mutex
	m  map[uint64]*probe
}

// probeTable is a sharded hash map of in-flight probes. The sniffer claims a
// probe with take() so an answer and a timeout can never both win.
type probeTable struct {
	shards [probeShards]probeShard
	count  atomic.Int64
}

func (t *probeTable) shardFor(key uint64) *probeShard {
	return &t.shards[key&(probeShards-1)]
}

// insert stores p and returns the probe it displaced, if any.
func (t *probeTable) insert(p *probe) *probe {
	s := t.shardFor(p.key)
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[uint64]*probe, 128)
	}
	old := s.m[p.key]
	s.m[p.key] = p
	s.mu.Unlock()
	if old == nil {
		t.count.Add(1)
	}
	return old
}

// take removes and returns the probe with key.
func (t *probeTable) take(key uint64) *probe {
	s := t.shardFor(key)
	s.mu.Lock()
	p := s.m[key]
	if p != nil {
		delete(s.m, key)
	}
	s.mu.Unlock()
	if p != nil {
		t.count.Add(-1)
	}
	return p
}

// has reports whether a probe with key is in flight.
func (t *probeTable) has(key uint64) bool {
	s := t.shardFor(key)
	s.mu.Lock()
	_, ok := s.m[key]
	s.mu.Unlock()
	return ok
}

func (t *probeTable) size() int64 { return t.count.Load() }

// ---- retransmit timer heap --------------------------------------------

type probeItem struct {
	due int64
	p   *probe
}

type probeHeap []*probeItem

func (h probeHeap) Len() int           { return len(h) }
func (h probeHeap) Less(i, j int) bool { return h[i].due < h[j].due }
func (h probeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *probeHeap) Push(x any)        { *h = append(*h, x.(*probeItem)) }
func (h *probeHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}

// ---- rate limiter ------------------------------------------------------

// limiter is a token bucket that paces outbound probes.
type limiter struct {
	rate   float64
	tokens float64
	burst  float64
	last   time.Time
}

func newLimiter(pps int) *limiter {
	if pps <= 0 {
		pps = 1000
	}
	l := &limiter{rate: float64(pps), last: time.Now()}
	l.burst = math.Max(1, float64(pps)/50) // 20ms of burst
	l.tokens = l.burst
	return l
}

func (l *limiter) refill(now time.Time) {
	if now.After(l.last) {
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		l.last = now
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
}

// tryTake consumes one token if one is available.
func (l *limiter) tryTake() bool {
	l.refill(time.Now())
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// delay consumes one token, sleeping first when the bucket is empty.
func (l *limiter) delay() time.Duration {
	if l.tryTake() {
		return 0
	}
	l.refill(time.Now())
	d := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
	if d < 10*time.Microsecond {
		d = 10 * time.Microsecond
	}
	return d
}

// sleepFor is how long to wait before a token is available again.
func (l *limiter) sleepFor() time.Duration {
	d := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
	if d < 25*time.Microsecond {
		d = 25 * time.Microsecond
	}
	if d > 5*time.Millisecond {
		d = 5 * time.Millisecond
	}
	return d
}

// ---- probe generator ---------------------------------------------------

// pairGen enumerates (host, port, proto) triples.
//
// Sequential order is port-major: every host gets port 0, then every host gets
// port 1, and so on, so a subnet is scanned evenly instead of hammering one host
// with 65k SYNs in a burst. Shuffle mode walks the whole product space with a
// coprime stride, giving a random order with O(1) memory.
type pairGen struct {
	hosts   []uint32
	tcp     []uint16
	udp     []uint16
	total   uint64
	pos     uint64
	step    uint64
	start   uint64
	shuffle bool
}

func newPairGen(hosts []uint32, ports PortSet, shuffle bool) *pairGen {
	g := &pairGen{hosts: hosts, tcp: ports.TCP, udp: ports.UDP}
	g.total = uint64(len(hosts)) * uint64(ports.Total())
	if shuffle && g.total > 1 {
		g.start = rand.Uint64N(g.total)
		step := g.total/2 | 1 // odd; advance until coprime
		for i := uint64(0); i < 64 && gcd(step, g.total) != 1; i++ {
			step += 2
			if step >= g.total {
				step = 3
			}
		}
		g.step = step
	}
	return g
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// next yields the next probe target.
func (g *pairGen) next() (dst uint32, port uint16, proto uint8, ok bool) {
	if g.pos >= g.total {
		return 0, 0, 0, false
	}
	var idx uint64
	if g.shuffle {
		idx = (g.start + g.pos*g.step) % g.total
	} else {
		idx = g.pos
	}
	g.pos++

	nh := uint64(len(g.hosts))
	if nh == 0 {
		return 0, 0, 0, false
	}
	host := g.hosts[idx%nh]
	pi := idx / nh

	if n := uint64(len(g.tcp)); pi < n {
		return host, g.tcp[(pi+hostRot(host, n))%n], packet.ProtoTCP, true
	}
	pi -= uint64(len(g.tcp))
	n := uint64(len(g.udp))
	if n == 0 {
		return 0, 0, 0, false
	}
	return host, g.udp[(pi+hostRot(host, n))%n], packet.ProtoUDP, true
}

// hostRot spreads the port order between hosts so two hosts are not hit with
// the same port at the same instant.
func hostRot(host uint32, n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return (uint64(host)*2654435761 + 12345) % n
}

// ---- SYN scanner -------------------------------------------------------

// synScanner drives the stateless SYN/UDP scan: one goroutine injects frames
// through Npcap, one goroutine reads replies, and a sharded table records which
// probes are still outstanding.
type synScanner struct {
	cfg     *Config
	builder *packet.Builder
	send    *npcap.Handle
	recv    *npcap.Handle
	batch   *npcap.BatchQueue
	link    packet.Link
	srcIP   packet.IPv4
	srcMAC  packet.MAC
	macs    map[uint32]packet.MAC
	hosts   []uint32
	table   *probeTable
	cnt     *counters
	sport   uint32
	sendErr atomic.Uint64
	rxTotal atomic.Uint64
}

func newSYNScanner(cfg *Config, hosts []uint32, macs map[uint32]packet.MAC) *synScanner {
	b := packet.NewBuilder(cfg.link)
	b.TTL = cfg.TTL
	return &synScanner{
		cfg:     cfg,
		builder: b,
		link:    cfg.link,
		srcIP:   cfg.srcIP,
		srcMAC:  cfg.srcMAC,
		macs:    macs,
		hosts:   hosts,
		table:   &probeTable{},
		cnt:     &counters{},
	}
}

// run executes the scan and returns once every probe has a verdict.
func (s *synScanner) run(ctx context.Context) {
	s.cnt.probes.Store(uint64(len(s.hosts)) * uint64(s.cfg.Scope.Ports.Total()))

	sniffDone := make(chan struct{})
	go func() {
		defer close(sniffDone)
		s.sniffLoop()
	}()

	gen := newPairGen(s.hosts, s.cfg.Scope.Ports, s.cfg.Shuffle)
	ch := make(chan probeReq, 8192)
	go func() {
		defer close(ch)
		for {
			dst, port, proto, ok := gen.next()
			if !ok {
				return
			}
			select {
			case ch <- probeReq{dst: dst, port: port, proto: proto}:
			case <-ctx.Done():
				return
			}
		}
	}()

	s.sendLoop(ctx, ch)

	// Give late replies a brief chance, then stop capture.
	time.Sleep(60 * time.Millisecond)
	s.recv.Close()
	<-sniffDone
}

func (s *synScanner) sendLoop(ctx context.Context, ch <-chan probeReq) {
	buf := make([]byte, s.frameBufSize())
	lim := newLimiter(s.cfg.Rate)
	h := &probeHeap{}
	heap.Init(h)
	genOpen := true
	var pending *probeReq
	lastReport := time.Now()
	s.cnt.beginSend()
	defer s.cnt.endSend()

	for {
		// 1. retransmit or expire everything that is due
		for h.Len() > 0 {
			top := (*h)[0]
			if top.due > time.Now().UnixNano() {
				break
			}
			it := heap.Pop(h).(*probeItem)
			p := it.p
			if p.due != it.due || p.state.Load() != pPending {
				continue // superseded or already answered
			}
			if int(p.retries) >= s.cfg.Retries {
				st := pFiltered
				if p.proto == packet.ProtoUDP {
					st = pOpenFiltered
				}
				s.finish(p, st)
				continue
			}
			p.retries++
			s.transmit(p, buf)
			s.cnt.retransmits.Add(1)
			p.due = time.Now().Add(s.retransInterval(p.retries)).UnixNano()
			heap.Push(h, &probeItem{due: p.due, p: p})
		}

		// 2. inject fresh probes while the rate budget allows
		sent := 0
		for sent < 2048 && genOpen {
			if pending == nil {
				select {
				case r, ok := <-ch:
					if !ok {
						genOpen = false
					} else {
						pending = &r
					}
				default:
					pending = nil
					goto drain
				}
				if !genOpen {
					break
				}
			}
			if !lim.tryTake() {
				break
			}
			s.dispatch(pending.dst, pending.port, pending.proto, buf, h)
			pending = nil
			sent++
		}

	drain:
		s.flushBatch()
		if !genOpen && h.Len() == 0 {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if sent == 0 {
			select {
			case <-time.After(lim.sleepFor()):
			case <-ctx.Done():
				return
			}
		}
		if s.cfg.Progress != nil && time.Since(lastReport) > 500*time.Millisecond {
			lastReport = time.Now()
			s.cfg.Progress(s.stats())
		}
	}
}

// dispatch builds and sends one probe, registers it and schedules its timer.
func (s *synScanner) dispatch(dst uint32, port uint16, proto uint8, buf []byte, h *probeHeap) {
	if _, ok := s.macs[dst]; !ok {
		s.cnt.done.Add(1) // no next-hop MAC: host never answered ARP
		return
	}
	var p *probe
	for attempt := 0; attempt < 16; attempt++ {
		sport := uint16(sportLow + (s.sport % sportSpan))
		s.sport++
		cand := &probe{
			key:   makeKey(dst, port, sport),
			dst:   dst,
			dport: port,
			sport: sport,
			seq:   rand.Uint32(),
			proto: proto,
		}
		if s.table.has(cand.key) {
			continue // this source port is still in flight, take the next one
		}
		s.table.insert(cand)
		p = cand
		break
	}
	if p == nil {
		s.cnt.done.Add(1)
		return
	}
	s.transmit(p, buf)
	p.due = time.Now().Add(s.retransInterval(0)).UnixNano()
	heap.Push(h, &probeItem{due: p.due, p: p})
}

// frameBufSize is the largest frame this scan can build: header + TCP SYN, or
// header + UDP with the biggest protocol probe payload.
func (s *synScanner) frameBufSize() int {
	maxPayload := 0
	for _, p := range s.cfg.Scope.Ports.UDP {
		if n := len(udpPayload(p)); n > maxPayload {
			maxPayload = n
		}
	}
	size := s.builder.MaxFrameUDP(maxPayload)
	if tcp := s.builder.MaxFrameTCP(); tcp > size {
		size = tcp
	}
	return size
}

// transmit writes the probe frame on the wire.
func (s *synScanner) transmit(p *probe, buf []byte) {
	mac, ok := s.macs[p.dst]
	if !ok {
		return
	}
	dst := packet.IPv4FromUint32(p.dst)
	var n int
	if p.proto == packet.ProtoTCP {
		n = s.builder.BuildTCPSYN(buf, mac, s.srcMAC, s.srcIP, dst, p.sport, p.dport, p.seq)
	} else {
		n = s.builder.BuildUDP(buf, mac, s.srcMAC, s.srcIP, dst, p.sport, p.dport, udpPayload(p.dport))
	}
	if n == 0 {
		s.cfg.logf("报文缓冲区过小，跳过 %s:%d", dst, p.dport)
		return
	}
	p.echo = time.Now().UnixNano()

	// Batched path: queue the frame and let the driver transmit a whole batch at
	// once. This is roughly an order of magnitude faster on Windows.
	if s.batch != nil && s.batch.Usable {
		if s.batch.Add(buf[:n]) {
			s.cnt.sent.Add(1)
			return
		}
		s.flushBatch()
		if s.batch.Add(buf[:n]) {
			s.cnt.sent.Add(1)
			return
		}
		// The device refuses batching: fall back to single-packet injection.
		s.batch.Free()
		s.batch = nil
	}

	if err := s.send.SendPacket(buf[:n]); err != nil {
		if s.sendErr.Add(1) == 1 {
			s.cfg.logf("发送报文失败：%v", err)
		}
		return
	}
	s.cnt.sent.Add(1)
}

// flushBatch transmits anything queued in the batch buffer.
func (s *synScanner) flushBatch() {
	if s.batch == nil || !s.batch.Usable || s.batch.Len() == 0 {
		return
	}
	if _, err := s.batch.Transmit(); err != nil {
		if s.sendErr.Add(1) == 1 {
			s.cfg.logf("%v", err)
		}
	}
}

// retransInterval is the per-attempt timeout, backing off exponentially.
func (s *synScanner) retransInterval(retries uint8) time.Duration {
	base := s.cfg.Timeout
	if base <= 0 {
		base = 400 * time.Millisecond
	}
	d := base * time.Duration(uint32(1)<<retries)
	if d > 4*base {
		d = 4 * base
	}
	return d
}

// finish resolves a probe exactly once and reports it.
func (s *synScanner) finish(p *probe, st uint32) {
	if !p.state.CompareAndSwap(pPending, st) {
		return
	}
	s.table.take(p.key)
	s.cnt.done.Add(1)
	switch st {
	case pOpen:
		s.cnt.open.Add(1)
	case pClosed:
		s.cnt.closed.Add(1)
	default:
		s.cnt.filtered.Add(1)
	}
	if !s.shouldReport(st) {
		return
	}
	var rtt time.Duration
	if p.echo != 0 && (st == pOpen || st == pClosed) {
		rtt = time.Since(time.Unix(0, p.echo))
	}
	proto := "tcp"
	if p.proto == packet.ProtoUDP {
		proto = "udp"
	}
	s.cfg.emit(Result{
		Host:    U32String(p.dst),
		Port:    p.dport,
		Proto:   proto,
		State:   probeStateName(st),
		Service: ServiceName(p.dport),
		RTT:     rtt,
	})
}

func (s *synScanner) shouldReport(st uint32) bool {
	switch st {
	case pOpen:
		return true
	case pClosed:
		return s.cfg.ShowClosed
	default:
		return s.cfg.ShowFiltered
	}
}

func probeStateName(st uint32) string {
	switch st {
	case pOpen:
		return StateOpen.String()
	case pClosed:
		return StateClosed.String()
	case pOpenFiltered:
		return StateOpenFiltered.String()
	default:
		return StateFiltered.String()
	}
}

func (s *synScanner) stats() Stats {
	return s.cnt.snapshot(s.cfg.startedAt, len(s.hosts), s.cfg.hostsDead, 0)
}

// sniffLoop reads captured frames and resolves probes.
func (s *synScanner) sniffLoop() {
	for {
		frame, err := s.recv.NextPacket()
		if err != nil {
			return
		}
		if frame == nil {
			continue
		}
		s.rxTotal.Add(1)
		s.handleFrame(frame)
	}
}

// handleFrame classifies one captured frame.
func (s *synScanner) handleFrame(frame []byte) {
	if tv, ok := packet.ParseTCP(frame, s.link); ok {
		if tv.DstIP != s.srcIP {
			return
		}
		if int(tv.DstPort) < sportLow || int(tv.DstPort) > sportHigh {
			return
		}
		key := makeKey(tv.SrcIP.Uint32(), tv.SrcPort, tv.DstPort)
		var st uint32
		switch {
		case tv.HasFlag(packet.FlagSYN) && tv.HasFlag(packet.FlagACK):
			st = pOpen
		case tv.HasFlag(packet.FlagRST):
			st = pClosed
		default:
			return
		}
		p := s.table.take(key)
		if p == nil {
			return
		}
		// Validate the sequence space so unrelated traffic cannot forge a result.
		if st == pOpen && tv.Ack != p.seq+1 {
			s.table.insert(p)
			return
		}
		if st == pClosed && !(tv.HasFlag(packet.FlagACK) && tv.Ack == p.seq+1) && tv.Seq != p.seq+1 {
			s.table.insert(p)
			return
		}
		s.cnt.received.Add(1)
		s.finish(p, st)
		return
	}

	if uv, ok := packet.ParseUDP(frame, s.link); ok {
		if uv.DstIP != s.srcIP {
			return
		}
		if int(uv.DstPort) < sportLow || int(uv.DstPort) > sportHigh {
			return
		}
		key := makeKey(uv.SrcIP.Uint32(), uv.SrcPort, uv.DstPort)
		if p := s.table.take(key); p != nil {
			s.cnt.received.Add(1)
			s.finish(p, pOpen)
		}
		return
	}

	if iv, ok := packet.ParseICMP(frame, s.link); ok {
		if iv.Type != 3 || !iv.HasInner {
			return
		}
		if iv.InnerSrcIP != s.srcIP {
			return
		}
		key := makeKey(iv.InnerDstIP.Uint32(), iv.InnerDstPort, iv.InnerSrcPort)
		p := s.table.take(key)
		if p == nil {
			return
		}
		switch iv.Code {
		case 3, 4: // port unreachable / fragmentation needed
			s.finish(p, pClosed)
		case 0, 1, 2, 13: // net/host/protocol unreachable, admin prohibited
			s.finish(p, pFiltered)
		default:
			s.table.insert(p)
		}
	}
}
