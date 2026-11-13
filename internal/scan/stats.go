package scan

import (
	"fmt"
	"sync/atomic"
	"time"
)

// State is the outcome of a single port probe.
type State uint8

const (
	// StateOpen means a TCP SYN-ACK or a UDP reply was received.
	StateOpen State = iota
	// StateClosed means the host answered with RST (TCP) or ICMP unreachable (UDP).
	StateClosed
	// StateFiltered means nothing came back: a firewall dropped the probe.
	StateFiltered
	// StateOpenFiltered is the UDP "silence" verdict: no reply and no ICMP.
	StateOpenFiltered
)

// String renders the state the way nmap-style tools do.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateFiltered:
		return "filtered"
	case StateOpenFiltered:
		return "open|filtered"
	default:
		return "unknown"
	}
}

// Result is one finding produced by the scanner.
type Result struct {
	Host    string        `json:"host"`
	Port    uint16        `json:"port"`
	Proto   string        `json:"proto"`
	State   string        `json:"state"`
	Service string        `json:"service,omitempty"`
	Banner  string        `json:"banner,omitempty"`
	RTT     time.Duration `json:"-"`
	RTTMs   float64       `json:"rtt_ms"`
	At      string        `json:"at"`
}

// Stats is a snapshot of engine progress, safe to read from another goroutine.
type Stats struct {
	Sent        uint64
	Retransmits uint64
	Received    uint64
	Open        uint64
	Closed      uint64
	Filtered    uint64
	Probes      uint64 // total planned probes
	Done        uint64 // probes resolved
	Hosts       int
	HostsDead   int
	Elapsed     time.Duration
	PPS         float64
	Dropped     uint32
}

// counters holds the live engine counters.
type counters struct {
	sent        atomic.Uint64
	retransmits atomic.Uint64
	received    atomic.Uint64
	open        atomic.Uint64
	closed      atomic.Uint64
	filtered    atomic.Uint64
	probes      atomic.Uint64
	done        atomic.Uint64

	// Sending window, used to report a meaningful packet rate. The total wall
	// clock includes ARP discovery and the retransmit drain, which would make
	// the rate look artificially low.
	sendStart atomic.Int64
	sendEnd   atomic.Int64
}

// beginSend records when injection starts.
func (c *counters) beginSend() { c.sendStart.Store(time.Now().UnixNano()) }

// endSend records when injection stops.
func (c *counters) endSend() { c.sendEnd.Store(time.Now().UnixNano()) }

// sendWindow returns the injection duration, falling back to the scan duration.
func (c *counters) sendWindow(scanElapsed time.Duration) time.Duration {
	start, end := c.sendStart.Load(), c.sendEnd.Load()
	if start > 0 && end >= start {
		if d := time.Duration(end - start); d > 0 {
			return d
		}
	}
	return scanElapsed
}

// snapshot builds a Stats value from the live counters.
func (c *counters) snapshot(start time.Time, hosts, dead int, dropped uint32) Stats {
	elapsed := time.Since(start)
	pps := 0.0
	if secs := c.sendWindow(elapsed).Seconds(); secs > 0 {
		pps = float64(c.sent.Load()) / secs
	}
	return Stats{
		Sent:        c.sent.Load(),
		Retransmits: c.retransmits.Load(),
		Received:    c.received.Load(),
		Open:        c.open.Load(),
		Closed:      c.closed.Load(),
		Filtered:    c.filtered.Load(),
		Probes:      c.probes.Load(),
		Done:        c.done.Load(),
		Hosts:       hosts,
		HostsDead:   dead,
		Elapsed:     elapsed,
		PPS:         pps,
		Dropped:     dropped,
	}
}

// Progress is the percentage of probes that have reached a verdict.
func (s Stats) Progress() float64 {
	if s.Probes == 0 {
		return 0
	}
	return 100 * float64(s.Done) / float64(s.Probes)
}

// String renders a compact progress line.
func (s Stats) String() string {
	return fmt.Sprintf("%5.1f%%  sent=%d  open=%d  closed=%d  filtered=%d  %.0f pps  %s",
		s.Progress(), s.Sent, s.Open, s.Closed, s.Filtered, s.PPS, s.Elapsed.Round(time.Millisecond))
}
