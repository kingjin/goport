package scan

import (
	"context"
	"sync"
	"time"

	"goport/internal/npcap"
	"goport/internal/packet"
)

// arpResolve fills a MAC table for the given targets by sending ARP requests and
// collecting the replies. It is used for on-link targets (and for the gateway of
// off-link targets), because a raw SYN frame needs the next-hop MAC.
//
// Requests are spread over timeout; targets that do not answer (no host,
// firewall, or a subnet too large for the timeout) are absent from the result
// and therefore skipped by the scanner.
func arpResolve(ctx context.Context, dev string, srcIP packet.IPv4, srcMAC packet.MAC, targets []uint32, timeout time.Duration, rate int, seed map[uint32]packet.MAC) (map[uint32]packet.MAC, error) {
	out := make(map[uint32]packet.MAC, len(targets))
	var pending []uint32
	for _, t := range targets {
		if mac, ok := seed[t]; ok {
			out[t] = mac
			continue
		}
		pending = append(pending, t)
	}
	if len(pending) == 0 {
		return out, nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if rate <= 0 {
		rate = 2000
	}

	sendH, err := npcap.OpenLive(dev, 65536, 20, false)
	if err != nil {
		return nil, err
	}
	defer sendH.Close()
	recvH, err := npcap.OpenLive(dev, 65536, 50, true)
	if err != nil {
		return nil, err
	}
	defer recvH.Close()
	if err := recvH.SetFilter("arp"); err != nil {
		return nil, err
	}

	var mu sync.Mutex
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			frame, err := recvH.NextPacket()
			if err != nil {
				return
			}
			if frame == nil {
				continue
			}
			v, ok := packet.ParseARP(frame, packet.LinkEthernet)
			if !ok || v.Op != 2 {
				continue
			}
			var mac packet.MAC
			copy(mac[:], v.SenderMAC[:])
			mu.Lock()
			out[v.SenderIP.Uint32()] = mac
			mu.Unlock()
		}
	}()

	deadline := time.Now().Add(timeout)
	buf := make([]byte, packet.EthHeaderLen+packet.ARPHeaderLen)
	lim := newLimiter(rate)

	unresolved := func() []uint32 {
		mu.Lock()
		defer mu.Unlock()
		res := make([]uint32, 0, len(pending))
		for _, t := range pending {
			if _, ok := out[t]; !ok {
				res = append(res, t)
			}
		}
		return res
	}

sendLoop:
	for round := 0; round < 3; round++ {
		list := unresolved()
		if len(list) == 0 {
			break
		}
		for _, t := range list {
			if ctx.Err() != nil || time.Now().After(deadline) {
				break sendLoop
			}
			n := packet.BuildARPRequest(buf, srcMAC, srcIP, packet.IPv4FromUint32(t))
			_ = sendH.SendPacket(buf[:n])
			if d := lim.delay(); d > 0 {
				time.Sleep(d)
			}
		}
		if wait := minDuration(150*time.Millisecond, time.Until(deadline)); wait > 0 {
			time.Sleep(wait)
		}
	}

	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
	close(stop)
	recvH.BreakLoop()
	<-readerDone

	mu.Lock()
	defer mu.Unlock()
	res := make(map[uint32]packet.MAC, len(out))
	for k, v := range out {
		res[k] = v
	}
	return res, nil
}

// usableMAC rejects empty, broadcast and multicast answers.
func usableMAC(m packet.MAC) bool {
	return !m.IsZero() && !m.IsBroadcast() && m[0]&0x01 == 0
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
