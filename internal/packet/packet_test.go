package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	testSrcMAC = MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testDstMAC = MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testSrcIP  = IPv4{192, 168, 1, 10}
	testDstIP  = IPv4{192, 168, 1, 20}
)

func TestBuildTCPSYNChecksums(t *testing.T) {
	b := NewBuilder(LinkEthernet)
	buf := make([]byte, b.MaxFrameTCP())
	n := b.BuildTCPSYN(buf, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 40000, 443, 0xdeadbeef)
	if n != 54 {
		t.Fatalf("frame length = %d, want 54", n)
	}
	frame := buf[:n]

	if got := MAC(frame[0:6]); got != testDstMAC {
		t.Errorf("dst mac = %v, want %v", got, testDstMAC)
	}
	if got := MAC(frame[6:12]); got != testSrcMAC {
		t.Errorf("src mac = %v, want %v", got, testSrcMAC)
	}
	if et := binary.BigEndian.Uint16(frame[12:14]); et != EthTypeIPv4 {
		t.Errorf("ethertype = %#x", et)
	}

	ip := frame[14 : 14+IPv4HeaderLen]
	if got := binary.BigEndian.Uint16(ip[2:4]); got != 40 {
		t.Errorf("ip total length = %d, want 40", got)
	}
	if !VerifyIPChecksum(ip) {
		t.Errorf("IPv4 header checksum invalid")
	}
	if !VerifyTransportChecksum(frame[14:]) {
		t.Errorf("TCP checksum invalid")
	}

	tcp := frame[14+IPv4HeaderLen:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != 40000 {
		t.Errorf("sport = %d", got)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != 443 {
		t.Errorf("dport = %d", got)
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0xdeadbeef {
		t.Errorf("seq = %#x", got)
	}
	if tcp[13] != FlagSYN {
		t.Errorf("flags = %#x, want SYN", tcp[13])
	}
	if tcp[12]>>4 != 5 {
		t.Errorf("data offset = %d, want 5", tcp[12]>>4)
	}
}

func TestBuildUDPChecksums(t *testing.T) {
	b := NewBuilder(LinkEthernet)
	payload := []byte("hello-port")
	buf := make([]byte, b.MaxFrameUDP(len(payload)))
	n := b.BuildUDP(buf, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 5353, 53, payload)
	frame := buf[:n]
	ip := frame[14:]
	if !VerifyIPChecksum(ip[:IPv4HeaderLen]) {
		t.Error("IPv4 header checksum invalid")
	}
	if !VerifyTransportChecksum(ip) {
		t.Error("UDP checksum invalid")
	}
	got := frame[n-len(payload):]
	if string(got) != string(payload) {
		t.Errorf("payload = %q", got)
	}
	v, ok := ParseUDP(frame, LinkEthernet)
	if !ok {
		t.Fatal("ParseUDP failed")
	}
	if v.SrcPort != 5353 || v.DstPort != 53 || v.SrcIP != testSrcIP || v.DstIP != testDstIP {
		t.Errorf("parsed udp = %+v", v)
	}
}

func TestBuildARPRequest(t *testing.T) {
	buf := make([]byte, 42)
	n := BuildARPRequest(buf, testSrcMAC, testSrcIP, testDstIP)
	if n != 42 {
		t.Fatalf("n = %d", n)
	}
	if !MAC(buf[0:6]).IsBroadcast() {
		t.Error("ARP request should broadcast")
	}
	v, ok := ParseARP(buf[:n], LinkEthernet)
	if !ok {
		t.Fatal("ParseARP failed")
	}
	if v.Op != 1 || v.SenderIP != testSrcIP || v.TargetIP != testDstIP || v.SenderMAC != testSrcMAC {
		t.Errorf("parsed arp = %+v", v)
	}
}

func TestParseTCPRoundsTrip(t *testing.T) {
	b := NewBuilder(LinkNull)
	buf := make([]byte, b.MaxFrameTCP())
	n := b.BuildTCPSYN(buf, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1234, 80, 0x11223344)
	v, ok := ParseTCP(buf[:n], LinkNull)
	if !ok {
		t.Fatal("ParseTCP on loopback link failed")
	}
	if v.SrcPort != 1234 || v.DstPort != 80 || v.Seq != 0x11223344 || !v.HasFlag(FlagSYN) {
		t.Errorf("parsed = %+v", v)
	}
	if v.SrcIP != testSrcIP || v.DstIP != testDstIP {
		t.Errorf("ips = %v -> %v", v.SrcIP, v.DstIP)
	}
}

func TestParseICMPUnreachable(t *testing.T) {
	// Hand-build an ICMP port-unreachable quoting a UDP packet we "sent".
	b := NewBuilder(LinkEthernet)
	orig := make([]byte, b.MaxFrameUDP(0))
	n := b.BuildUDP(orig, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 40001, 161, nil)
	origIP := orig[14:n]

	const icmpLen = 8 + IPv4HeaderLen + 8
	frame := make([]byte, 14+IPv4HeaderLen+icmpLen)
	copy(frame[0:6], testSrcMAC[:])
	copy(frame[6:12], testDstMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], EthTypeIPv4)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(IPv4HeaderLen+icmpLen))
	ip[8] = 64
	ip[9] = ProtoICMP
	copy(ip[12:16], testDstIP[:])
	copy(ip[16:20], testSrcIP[:])
	binary.BigEndian.PutUint16(ip[10:12], Checksum(ip[:IPv4HeaderLen]))
	icmp := frame[14+IPv4HeaderLen:]
	icmp[0], icmp[1] = 3, 3
	copy(icmp[8:], origIP)

	v, ok := ParseICMP(frame, LinkEthernet)
	if !ok {
		t.Fatal("ParseICMP failed")
	}
	if v.Type != 3 || v.Code != 3 {
		t.Fatalf("type/code = %d/%d", v.Type, v.Code)
	}
	if !v.HasInner {
		t.Fatal("inner packet not parsed")
	}
	if v.InnerSrcIP != testSrcIP || v.InnerDstIP != testDstIP || v.InnerSrcPort != 40001 || v.InnerDstPort != 161 {
		t.Errorf("inner = %v:%d -> %v:%d", v.InnerSrcIP, v.InnerSrcPort, v.InnerDstIP, v.InnerDstPort)
	}
	if v.InnerProto != ProtoUDP {
		t.Errorf("inner proto = %d", v.InnerProto)
	}
}

func TestParseRejectsTruncatedFrames(t *testing.T) {
	full := make([]byte, 54)
	b := NewBuilder(LinkEthernet)
	b.BuildTCPSYN(full, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1, 2, 3)
	for _, n := range []int{0, 13, 20, 33, 53} {
		if _, ok := ParseTCP(full[:n], LinkEthernet); ok {
			t.Errorf("ParseTCP accepted a %d byte frame", n)
		}
	}
}

func TestBuilderRejectsSmallBuffers(t *testing.T) {
	b := NewBuilder(LinkEthernet)
	if n := b.BuildTCPSYN(make([]byte, 10), testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1, 2, 3); n != 0 {
		t.Errorf("BuildTCPSYN on a 10 byte buffer returned %d, want 0", n)
	}
	if n := b.BuildUDP(make([]byte, 20), testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1, 2, []byte("payload")); n != 0 {
		t.Errorf("BuildUDP on a 20 byte buffer returned %d, want 0", n)
	}
	// A payload that only fits in a larger buffer must not overflow either.
	big := make([]byte, b.MaxFrameUDP(300))
	if n := b.BuildUDP(big, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1, 2, make([]byte, 300)); n == 0 {
		t.Error("BuildUDP should succeed for a correctly sized buffer")
	}
	if n := b.BuildUDP(big, testDstMAC, testSrcMAC, testSrcIP, testDstIP, 1, 2, make([]byte, 301)); n != 0 {
		t.Errorf("BuildUDP should refuse an oversized payload, returned %d", n)
	}
	if b.MaxFrameUDP(0) != 42 || b.MaxFrameTCP() != 54 {
		t.Errorf("frame sizes: udp=%d tcp=%d", b.MaxFrameUDP(0), b.MaxFrameTCP())
	}
}

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 example: the one's complement sum of 00 01 f2 03 f4 f5 f6 f7 is
	// 0xddf2, so the checksum is ~0xddf2 = 0x220d.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := Checksum(data); got != 0x220d {
		t.Errorf("Checksum = %#04x, want 0x220d", got)
	}
}

func TestMACAndIPv4Helpers(t *testing.T) {
	m, err := ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil || m != testDstMAC {
		t.Fatalf("ParseMAC = %v, %v", m, err)
	}
	if got := m.String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("String = %q", got)
	}
	if _, err := ParseMAC("zz:bb:cc:dd:ee:ff"); err == nil {
		t.Error("ParseMAC accepted garbage")
	}
	a, ok := IPv4From(netip.MustParseAddr("10.0.0.1"))
	if !ok || a.Uint32() != 0x0a000001 {
		t.Errorf("IPv4From = %v %v", a, ok)
	}
	if got := IPv4FromUint32(0x0a000001); got != a {
		t.Errorf("IPv4FromUint32 = %v", got)
	}
}
