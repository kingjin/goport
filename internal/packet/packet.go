// Package packet crafts and parses raw Ethernet/IPv4/TCP/UDP/ARP frames.
//
// It is written from scratch on top of encoding/binary so the scanner has no
// third-party dependencies: gopacket/pcap is avoided both because it forces cgo
// and because a SYN scanner only needs a few dozen bytes of header logic.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// EtherTypes and IP protocol numbers.
const (
	EthTypeIPv4 = 0x0800
	EthTypeARP  = 0x0806

	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// TCP flags.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
)

// Fixed header sizes.
const (
	EthHeaderLen  = 14
	IPv4HeaderLen = 20
	TCPHeaderLen  = 20
	UDPHeaderLen  = 8
	ARPHeaderLen  = 28
	NullHeaderLen = 4 // BSD loopback: 4-byte address family
)

// Link is the link-layer encapsulation of the capture device.
type Link uint8

const (
	LinkEthernet Link = iota // DLT_EN10MB
	LinkNull                 // DLT_NULL, 4-byte AF_INET header (Npcap loopback with DltNull=1)
)

// HeaderLen is the number of link-layer bytes preceding the IPv4 header.
func (l Link) HeaderLen() int {
	if l == LinkNull {
		return NullHeaderLen
	}
	return EthHeaderLen
}

// String names the link type for diagnostics.
func (l Link) String() string {
	if l == LinkNull {
		return "null/loopback"
	}
	return "ethernet"
}

// MAC is a 48-bit Ethernet address.
type MAC [6]byte

// String renders the address in colon notation.
func (m MAC) String() string {
	var b [17]byte
	const hex = "0123456789abcdef"
	for i, c := range m {
		b[i*3] = hex[c>>4]
		b[i*3+1] = hex[c&0x0f]
		if i != 5 {
			b[i*3+2] = ':'
		}
	}
	return string(b[:])
}

// IsBroadcast reports whether this is the all-ones address.
func (m MAC) IsBroadcast() bool { return m == MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} }

// IsZero reports whether the address is unset.
func (m MAC) IsZero() bool { return m == MAC{} }

// ParseMAC parses "aa:bb:cc:dd:ee:ff" or "aabbccddeeff".
func ParseMAC(s string) (MAC, error) {
	var m MAC
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", ":")
	if !strings.Contains(s, ":") && len(s) == 12 {
		for i := 0; i < 6; i++ {
			v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
			if err != nil {
				return m, fmt.Errorf("MAC 地址无效 %q", s)
			}
			m[i] = byte(v)
		}
		return m, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return m, fmt.Errorf("MAC 地址无效 %q", s)
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return m, fmt.Errorf("MAC 地址无效 %q", s)
		}
		m[i] = byte(v)
	}
	return m, nil
}

// IPv4 is an IPv4 address in network byte order.
type IPv4 [4]byte

// String renders the address in dotted notation.
func (a IPv4) String() string {
	return netip.AddrFrom4(a).String()
}

// Addr converts to netip.Addr.
func (a IPv4) Addr() netip.Addr { return netip.AddrFrom4(a) }

// Uint32 returns the address in host order for hashing and comparisons.
func (a IPv4) Uint32() uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// IPv4FromUint32 converts a host-order uint32 back to an address.
func IPv4FromUint32(v uint32) IPv4 {
	return IPv4{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// IPv4From converts a netip.Addr into an IPv4 if it is IPv4-mapped.
func IPv4From(a netip.Addr) (IPv4, bool) {
	a = a.Unmap()
	if !a.Is4() {
		return IPv4{}, false
	}
	return IPv4(a.As4()), true
}

// Builder writes frames using per-scan constants such as TTL, TCP window and
// the link-layer encapsulation.
type Builder struct {
	Link   Link
	TTL    uint8
	Window uint16
	ipID   uint32
}

// NewBuilder returns a Builder with sensible defaults.
func NewBuilder(link Link) *Builder {
	return &Builder{Link: link, TTL: 64, Window: 65535}
}

// MaxFrameTCP is the buffer size needed for a TCP SYN frame.
func (b *Builder) MaxFrameTCP() int { return b.Link.HeaderLen() + IPv4HeaderLen + TCPHeaderLen }

// MaxFrameUDP is the buffer size needed for a UDP frame with payload.
func (b *Builder) MaxFrameUDP(payload int) int {
	return b.Link.HeaderLen() + IPv4HeaderLen + UDPHeaderLen + payload
}

func (b *Builder) ttl() uint8 {
	if b.TTL == 0 {
		return 64
	}
	return b.TTL
}

func (b *Builder) window() uint16 {
	if b.Window == 0 {
		return 65535
	}
	return b.Window
}

// writeL2 writes the link-layer header and returns the offset of the IPv4 header.
func (b *Builder) writeL2(dst []byte, dmac, smac MAC) int {
	if b.Link == LinkNull {
		// DLT_NULL carries the AF in host byte order, little endian on Windows.
		binary.LittleEndian.PutUint32(dst, 2) // AF_INET
		return NullHeaderLen
	}
	copy(dst[0:6], dmac[:])
	copy(dst[6:12], smac[:])
	binary.BigEndian.PutUint16(dst[12:14], EthTypeIPv4)
	return EthHeaderLen
}

// writeIPv4 fills the IPv4 header for the given payload length.
func (b *Builder) writeIPv4(hdr []byte, sip, dip IPv4, proto uint8, payloadLen int) {
	hdr[0] = 0x45 // version 4, IHL 5
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:4], uint16(IPv4HeaderLen+payloadLen))
	b.ipID++
	binary.BigEndian.PutUint16(hdr[4:6], uint16(b.ipID))
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000) // DF, no fragment
	hdr[8] = b.ttl()
	hdr[9] = proto
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	copy(hdr[12:16], sip[:])
	copy(hdr[16:20], dip[:])
	binary.BigEndian.PutUint16(hdr[10:12], Checksum(hdr[:IPv4HeaderLen]))
}

// BuildTCPSYN writes a complete TCP SYN frame into dst and returns its length.
// It returns 0 when dst is too small, which lets callers detect a sizing bug
// instead of panicking on a slice bound.
func (b *Builder) BuildTCPSYN(dst []byte, dmac, smac MAC, sip, dip IPv4, sport, dport uint16, seq uint32) int {
	if len(dst) < b.MaxFrameTCP() {
		return 0
	}
	off := b.writeL2(dst, dmac, smac)
	ip := dst[off : off+IPv4HeaderLen]
	b.writeIPv4(ip, sip, dip, ProtoTCP, TCPHeaderLen)

	tcp := dst[off+IPv4HeaderLen : off+IPv4HeaderLen+TCPHeaderLen]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = 5 << 4 // data offset 5 words, no options
	tcp[13] = FlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], b.window())
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	sum := pseudoSum(sip, dip, ProtoTCP, TCPHeaderLen)
	sum = checksumSum(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], finishChecksum(sum))
	return off + IPv4HeaderLen + TCPHeaderLen
}

// BuildUDP writes a complete UDP frame into dst and returns its length.
// It returns 0 when dst is too small for the payload.
func (b *Builder) BuildUDP(dst []byte, dmac, smac MAC, sip, dip IPv4, sport, dport uint16, payload []byte) int {
	if len(dst) < b.MaxFrameUDP(len(payload)) {
		return 0
	}
	off := b.writeL2(dst, dmac, smac)
	ip := dst[off : off+IPv4HeaderLen]
	b.writeIPv4(ip, sip, dip, ProtoUDP, UDPHeaderLen+len(payload))

	udp := dst[off+IPv4HeaderLen : off+IPv4HeaderLen+UDPHeaderLen]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(UDPHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	body := dst[off+IPv4HeaderLen+UDPHeaderLen : off+IPv4HeaderLen+UDPHeaderLen+len(payload)]
	copy(body, payload)

	// A zero IPv4 checksum is legal for UDP; Linux/Win11 accept it. Compute the
	// real one anyway so middleboxes never complain.
	sum := pseudoSum(sip, dip, ProtoUDP, len(udp)+len(payload))
	sum = checksumSum(sum, udp)
	sum = checksumSum(sum, payload)
	final := finishChecksum(sum)
	if final == 0 {
		final = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], final)
	return off + IPv4HeaderLen + UDPHeaderLen + len(payload)
}

// BuildARPRequest writes an ARP request "who has target?" for the local subnet.
func BuildARPRequest(dst []byte, smac MAC, sip, target IPv4) int {
	broadcast := MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	copy(dst[0:6], broadcast[:])
	copy(dst[6:12], smac[:])
	binary.BigEndian.PutUint16(dst[12:14], EthTypeARP)

	arp := dst[EthHeaderLen : EthHeaderLen+ARPHeaderLen]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // hardware type: ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // protocol type: IPv4
	arp[4] = 6                                   // hardware length
	arp[5] = 4                                   // protocol length
	binary.BigEndian.PutUint16(arp[6:8], 1)      // opcode: request
	copy(arp[8:14], smac[:])
	copy(arp[14:18], sip[:])
	for i := 18; i < 24; i++ {
		arp[i] = 0
	}
	copy(arp[24:28], target[:])
	return EthHeaderLen + ARPHeaderLen
}

// ---- checksums ---------------------------------------------------------

func checksumSum(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Checksum computes the internet checksum (RFC 1071) of b.
func Checksum(b []byte) uint16 { return finishChecksum(checksumSum(0, b)) }

func pseudoSum(sip, dip IPv4, proto uint8, length int) uint32 {
	sum := checksumSum(0, sip[:])
	sum = checksumSum(sum, dip[:])
	sum += uint32(proto)  // zero byte + protocol
	sum += uint32(length) // TCP/UDP length
	return sum
}

// VerifyIPChecksum reports whether an IPv4 header's checksum is intact.
func VerifyIPChecksum(hdr []byte) bool {
	if len(hdr) < IPv4HeaderLen {
		return false
	}
	return Checksum(hdr[:IPv4HeaderLen]) == 0
}

// VerifyTransportChecksum reports whether a TCP/UDP segment inside an IPv4
// packet has a valid checksum. It is used by the unit tests and by -dry-run
// self-checks.
func VerifyTransportChecksum(pkt []byte) bool {
	if len(pkt) < IPv4HeaderLen {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < IPv4HeaderLen || total > len(pkt) || total < ihl {
		return false
	}
	proto := pkt[9]
	var sip, dip IPv4
	copy(sip[:], pkt[12:16])
	copy(dip[:], pkt[16:20])
	seg := pkt[ihl:total]
	sum := pseudoSum(sip, dip, proto, len(seg))
	sum = checksumSum(sum, seg)
	return finishChecksum(sum) == 0xffff || finishChecksum(sum) == 0
}

// ---- parsing -----------------------------------------------------------

// ErrTooShort is returned when a frame is smaller than its headers claim.
var ErrTooShort = errors.New("报文被截断")

// TCPView is a decoded TCP header from a captured frame.
type TCPView struct {
	SrcIP, DstIP     IPv4
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
}

// HasFlag reports whether all bits in f are set.
func (t TCPView) HasFlag(f uint8) bool { return t.Flags&f == f }

// UDPView is a decoded UDP header from a captured frame.
type UDPView struct {
	SrcIP, DstIP     IPv4
	SrcPort, DstPort uint16
}

// ICMPView is a decoded ICMP message. For error messages it also exposes the
// embedded IPv4 header and first four transport bytes of the original packet.
type ICMPView struct {
	Type, Code   uint8
	SrcIP, DstIP IPv4
	InnerSrcIP   IPv4
	InnerDstIP   IPv4
	InnerSrcPort uint16
	InnerDstPort uint16
	InnerProto   uint8
	HasInner     bool
}

// ARPView is a decoded ARP packet.
type ARPView struct {
	Op        uint16
	SenderIP  IPv4
	SenderMAC MAC
	TargetIP  IPv4
}

// ipv4At returns the IPv4 header start for a frame captured on link.
func ipv4At(frame []byte, link Link) (int, bool) {
	hl := link.HeaderLen()
	if len(frame) < hl+IPv4HeaderLen {
		return 0, false
	}
	if link == LinkNull {
		if binary.LittleEndian.Uint32(frame[0:4]) != 2 {
			return 0, false
		}
		return hl, true
	}
	if binary.BigEndian.Uint16(frame[12:14]) != EthTypeIPv4 {
		return 0, false
	}
	return hl, true
}

// ParseTCP decodes a TCP segment from a captured frame.
func ParseTCP(frame []byte, link Link) (TCPView, bool) {
	v, ok := parseIPProto(frame, link, ProtoTCP)
	if !ok {
		return TCPView{}, false
	}
	off, ihl, total := v.off, v.ihl, v.total
	if ihl+TCPHeaderLen > total {
		return TCPView{}, false
	}
	t := frame[off+ihl:]
	tv := TCPView{
		SrcIP:   v.src,
		DstIP:   v.dst,
		SrcPort: binary.BigEndian.Uint16(t[0:2]),
		DstPort: binary.BigEndian.Uint16(t[2:4]),
		Seq:     binary.BigEndian.Uint32(t[4:8]),
		Ack:     binary.BigEndian.Uint32(t[8:12]),
		Flags:   t[13],
	}
	return tv, true
}

// ParseUDP decodes a UDP datagram from a captured frame.
func ParseUDP(frame []byte, link Link) (UDPView, bool) {
	v, ok := parseIPProto(frame, link, ProtoUDP)
	if !ok {
		return UDPView{}, false
	}
	if v.ihl+UDPHeaderLen > v.total {
		return UDPView{}, false
	}
	u := frame[v.off+v.ihl:]
	return UDPView{
		SrcIP:   v.src,
		DstIP:   v.dst,
		SrcPort: binary.BigEndian.Uint16(u[0:2]),
		DstPort: binary.BigEndian.Uint16(u[2:4]),
	}, true
}

// ParseICMP decodes an ICMP message, including the quoted packet of errors.
func ParseICMP(frame []byte, link Link) (ICMPView, bool) {
	v, ok := parseIPProto(frame, link, ProtoICMP)
	if !ok {
		return ICMPView{}, false
	}
	if v.ihl+8 > v.total {
		return ICMPView{}, false
	}
	m := frame[v.off+v.ihl:]
	iv := ICMPView{
		Type:  m[0],
		Code:  m[1],
		SrcIP: v.src,
		DstIP: v.dst,
	}
	// ICMP errors quote the offending IPv4 header plus 8 bytes of payload.
	inner := m[8:]
	if iv.Type == 3 || iv.Type == 11 {
		if len(inner) >= IPv4HeaderLen && inner[0]>>4 == 4 {
			ihl := int(inner[0]&0x0f) * 4
			if ihl >= IPv4HeaderLen && len(inner) >= ihl+4 {
				copy(iv.InnerSrcIP[:], inner[12:16])
				copy(iv.InnerDstIP[:], inner[16:20])
				iv.InnerProto = inner[9]
				if len(inner) >= ihl+4 {
					iv.InnerSrcPort = binary.BigEndian.Uint16(inner[ihl : ihl+2])
					iv.InnerDstPort = binary.BigEndian.Uint16(inner[ihl+2 : ihl+4])
				}
				iv.HasInner = true
			}
		}
	}
	return iv, true
}

// ParseARP decodes an ARP packet.
func ParseARP(frame []byte, link Link) (ARPView, bool) {
	if link == LinkNull {
		return ARPView{}, false // loopback has no ARP
	}
	if len(frame) < EthHeaderLen+ARPHeaderLen {
		return ARPView{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != EthTypeARP {
		return ARPView{}, false
	}
	a := frame[EthHeaderLen : EthHeaderLen+ARPHeaderLen]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || a[4] != 6 || a[5] != 4 {
		return ARPView{}, false
	}
	v := ARPView{Op: binary.BigEndian.Uint16(a[6:8])}
	copy(v.SenderMAC[:], a[8:14])
	copy(v.SenderIP[:], a[14:18])
	copy(v.TargetIP[:], a[24:28])
	return v, true
}

type ipView struct {
	off, ihl, total int
	src, dst        IPv4
}

func parseIPProto(frame []byte, link Link, proto uint8) (ipView, bool) {
	off, ok := ipv4At(frame, link)
	if !ok {
		return ipView{}, false
	}
	ip := frame[off:]
	if ip[0]>>4 != 4 {
		return ipView{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if ihl < IPv4HeaderLen || total < ihl || off+total > len(frame) {
		return ipView{}, false
	}
	if ip[9] != proto {
		return ipView{}, false
	}
	// Non-first fragments carry no transport header.
	if binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
		return ipView{}, false
	}
	var v ipView
	v.off, v.ihl, v.total = off, ihl, total
	copy(v.src[:], ip[12:16])
	copy(v.dst[:], ip[16:20])
	return v, true
}
