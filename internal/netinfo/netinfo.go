// Package netinfo discovers Windows network configuration through iphlpapi.dll.
//
// Everything here (adapter list, default route, ARP cache) works without
// administrator privileges, unlike pcap_findalldevs which Npcap restricts to
// administrators. Adapter GUIDs are used to derive Npcap device names
// (\Device\NPF_{GUID}), so the scanner can list and select interfaces before
// it ever opens the driver.
package netinfo

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")
	procGetIpForwardTable    = modiphlpapi.NewProc("GetIpForwardTable")
	procGetIpNetTable        = modiphlpapi.NewProc("GetIpNetTable")
	procGetIpAddrTable       = modiphlpapi.NewProc("GetIpAddrTable")
)

const (
	afUnspec = 0

	// GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
	gaaSkipExtras = 0x2 | 0x4 | 0x8

	errorBufferOverflow     = 111
	errorInsufficientBuffer = 122

	ifOperStatusUp = 1
)

// Adapter is a Windows network interface plus the Npcap device name derived
// from its GUID.
type Adapter struct {
	Index    uint32 // IF_INDEX
	Name     string // NetCfgInstanceId, e.g. "{5F1A...}"
	Desc     string // driver description
	Friendly string // connection name shown in "网络连接"
	MAC      []byte
	Up       bool
	IfType   uint32
	IPv4     []netip.Addr
	Masks    []netip.Addr
	Device   string // \Device\NPF_{GUID} for Npcap
	Loopback bool
}

// Label is the human friendly name, falling back to the driver description.
func (a Adapter) Label() string {
	switch {
	case a.Friendly != "":
		return a.Friendly
	case a.Desc != "":
		return a.Desc
	default:
		return a.Name
	}
}

// String renders the row used by -list-if.
func (a Adapter) String() string {
	ip := "no ipv4"
	if len(a.IPv4) > 0 && len(a.Masks) > 0 {
		ip = fmt.Sprintf("%s/%d", a.IPv4[0], MaskBits(a.Masks[0]))
	}
	state := "down"
	if a.Up {
		state = "up"
	}
	return fmt.Sprintf("#%-2d %-30s %-18s %-17s %-4s %s", a.Index, truncate(a.Label(), 30), ip, a.MACString(), state, a.Desc)
}

// MACString renders the adapter MAC in colon notation.
func (a Adapter) MACString() string {
	if len(a.MAC) < 6 {
		return "-"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a.MAC[0], a.MAC[1], a.MAC[2], a.MAC[3], a.MAC[4], a.MAC[5])
}

// Prefix returns the adapter's first IPv4 prefix (address + mask).
func (a Adapter) Prefix() (netip.Prefix, bool) {
	if len(a.IPv4) == 0 || len(a.Masks) == 0 {
		return netip.Prefix{}, false
	}
	bits := MaskBits(a.Masks[0])
	if bits < 0 || bits > 32 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a.IPv4[0], bits), true
}

// MAC6 returns the adapter MAC as a fixed-size array.
func (a Adapter) MAC6() ([6]byte, bool) {
	var m [6]byte
	if len(a.MAC) < 6 {
		return m, false
	}
	copy(m[:], a.MAC[:6])
	return m, true
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// MaskBits converts a dotted netmask to its prefix length.
func MaskBits(m netip.Addr) int {
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for i := 31; i >= 0; i-- {
		if v&(1<<uint(i)) == 0 {
			break
		}
		n++
	}
	return n
}

// Adapters enumerates the local interfaces with their IPv4 configuration.
func Adapters() ([]Adapter, error) {
	addrs := ipv4Table()
	out, err := adapterList(addrs)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// adapterList walks IP_ADAPTER_ADDRESSES and merges the IPv4 table.
func adapterList(addrs map[uint32][]ipv4Entry) ([]Adapter, error) {
	size := uint32(32 * 1024)
	var buf []byte
	var ret uintptr
	for attempt := 0; attempt < 5; attempt++ {
		buf = make([]byte, size)
		ret, _, _ = procGetAdaptersAddresses.Call(
			afUnspec,
			gaaSkipExtras,
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret == 0 {
			break
		}
		if ret != errorBufferOverflow {
			return nil, fmt.Errorf("GetAdaptersAddresses 失败，错误码 %d", ret)
		}
	}
	if ret != 0 {
		return nil, errors.New("GetAdaptersAddresses 缓冲区不足")
	}

	ps := unsafe.Sizeof(uintptr(0))
	const base = 8 // the ULONGLONG alignment union at the head of the struct
	offNext := base
	offName := base + ps
	offDesc := base + 7*ps
	offFriendly := base + 8*ps
	offPhysAddr := base + 9*ps
	offPhysLen := offPhysAddr + 8
	offIfType := offPhysLen + 12
	offOper := offPhysLen + 16

	var out []Adapter
	for cur := unsafe.Pointer(&buf[0]); cur != nil; {
		if *(*uint32)(unsafe.Add(cur, 0)) < 64 {
			break // implausible struct length: stop instead of chasing garbage
		}
		a := Adapter{
			Index:    *(*uint32)(unsafe.Add(cur, 4)),
			Name:     goString(*(*unsafe.Pointer)(unsafe.Add(cur, offName))),
			Desc:     goWide(*(*unsafe.Pointer)(unsafe.Add(cur, offDesc))),
			Friendly: goWide(*(*unsafe.Pointer)(unsafe.Add(cur, offFriendly))),
			IfType:   *(*uint32)(unsafe.Add(cur, offIfType)),
			Up:       *(*uint32)(unsafe.Add(cur, offOper)) == ifOperStatusUp,
		}
		if physLen := *(*uint32)(unsafe.Add(cur, offPhysLen)); physLen > 0 && physLen <= 8 {
			mac := make([]byte, physLen)
			copy(mac, unsafe.Slice((*byte)(unsafe.Add(cur, offPhysAddr)), int(physLen)))
			a.MAC = mac
		}
		if a.Name != "" {
			a.Device = `\Device\NPF_` + a.Name
		}
		for _, e := range addrs[a.Index] {
			a.IPv4 = append(a.IPv4, e.IP)
			a.Masks = append(a.Masks, e.Mask)
		}
		out = append(out, a)
		cur = *(*unsafe.Pointer)(unsafe.Add(cur, offNext))
	}
	return out, nil
}

type ipv4Entry struct {
	IP   netip.Addr
	Mask netip.Addr
}

// ipv4Table reads MIB_IPADDRTABLE: address + netmask keyed by interface index.
func ipv4Table() map[uint32][]ipv4Entry {
	out := make(map[uint32][]ipv4Entry)
	size := uint32(16 * 1024)
	var buf []byte
	var ret uintptr
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		ret, _, _ = procGetIpAddrTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if ret == 0 {
			break
		}
		if ret != errorInsufficientBuffer && ret != errorBufferOverflow {
			return out
		}
	}
	if ret != 0 {
		return out
	}
	const rowSize = 24 // MIB_IPADDRROW: 6 DWORDs
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	for i := uint32(0); i < n; i++ {
		row := unsafe.Add(unsafe.Pointer(&buf[0]), 4+uintptr(i)*rowSize)
		addr := U32ToAddr(u32At(row, 0))
		ifIdx := *(*uint32)(unsafe.Add(row, 4))
		mask := U32ToAddr(u32At(row, 8))
		if addr.IsUnspecified() {
			continue
		}
		out[ifIdx] = append(out[ifIdx], ipv4Entry{IP: addr, Mask: mask})
	}
	return out
}

// LoopbackAdapter returns the synthetic Npcap loopback interface.
func LoopbackAdapter() Adapter {
	return Adapter{
		Index:    1,
		Name:     "Loopback",
		Desc:     "Npcap Loopback Adapter",
		Friendly: "Loopback",
		Up:       true,
		IfType:   24,
		IPv4:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Masks:    []netip.Addr{netip.MustParseAddr("255.0.0.0")},
		Device:   `\Device\NPF_Loopback`,
		Loopback: true,
	}
}

// Route is one entry of the IPv4 routing table.
type Route struct {
	Dest    uint32
	Mask    uint32
	NextHop netip.Addr
	IfIndex uint32
	Metric  uint32
}

// Routes returns the IPv4 routing table.
func Routes() []Route {
	size := uint32(8192)
	var buf []byte
	var ret uintptr
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		ret, _, _ = procGetIpForwardTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if ret == 0 {
			break
		}
		if ret != errorInsufficientBuffer && ret != errorBufferOverflow {
			return nil
		}
	}
	if ret != 0 {
		return nil
	}
	const rowSize = 56 // MIB_IPFORWARDROW: 14 DWORDs
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := make([]Route, 0, n)
	for i := uint32(0); i < n; i++ {
		row := unsafe.Add(unsafe.Pointer(&buf[0]), 4+uintptr(i)*rowSize)
		out = append(out, Route{
			Dest:    u32At(row, 0),
			Mask:    u32At(row, 4),
			NextHop: U32ToAddr(u32At(row, 12)),
			IfIndex: *(*uint32)(unsafe.Add(row, 16)),
			Metric:  *(*uint32)(unsafe.Add(row, 36)),
		})
	}
	return out
}

// DefaultRoute returns the interface index and next hop of the IPv4 default
// route (the lowest-metric 0.0.0.0/0 entry).
func DefaultRoute() (ifIndex uint32, gw netip.Addr, ok bool) {
	bestMetric := ^uint32(0)
	for _, r := range Routes() {
		if r.Dest != 0 || r.Mask != 0 {
			continue
		}
		if r.Metric < bestMetric {
			bestMetric = r.Metric
			gw = r.NextHop
			ifIndex = r.IfIndex
			ok = true
		}
	}
	return ifIndex, gw, ok
}

// RouteTo finds the route used for dst (longest prefix match, lowest metric).
func RouteTo(dst netip.Addr) (Route, bool) {
	v := AddrToU32(dst)
	var best Route
	bestLen := -1
	found := false
	for _, r := range Routes() {
		if v&r.Mask != r.Dest {
			continue
		}
		n := 32 - bitsInMask(r.Mask)
		if n > bestLen || (n == bestLen && found && r.Metric < best.Metric) {
			best, bestLen, found = r, n, true
		}
	}
	return best, found
}

func bitsInMask(m uint32) int {
	n := 0
	for i := 0; i < 32; i++ {
		if m&(1<<uint(i)) != 0 {
			n++
		}
	}
	return n
}

// ARPCache returns the IPv4→MAC mappings currently known to the OS. Seeding the
// scanner with this table avoids re-resolving hosts Windows already knows.
func ARPCache() map[netip.Addr][6]byte {
	out := make(map[netip.Addr][6]byte)
	size := uint32(8192)
	var buf []byte
	var ret uintptr
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		ret, _, _ = procGetIpNetTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if ret == 0 {
			break
		}
		if ret != errorInsufficientBuffer && ret != errorBufferOverflow {
			return out
		}
	}
	if ret != 0 {
		return out
	}
	const rowSize = 24 // MIB_IPNETROW
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	for i := uint32(0); i < n; i++ {
		row := unsafe.Add(unsafe.Pointer(&buf[0]), 4+uintptr(i)*rowSize)
		if *(*uint32)(unsafe.Add(row, 4)) != 6 { // physical address length
			continue
		}
		if *(*uint32)(unsafe.Add(row, 20)) == 5 { // MIB_IPNET_TYPE_INVALID
			continue
		}
		raw := unsafe.Slice((*byte)(unsafe.Add(row, 8)), 6)
		// Incomplete (all zero), multicast and broadcast entries are not usable
		// next hops, so they never enter the map.
		var mac [6]byte
		copy(mac[:], raw)
		if mac == [6]byte{} || mac[0]&0x01 != 0 {
			continue
		}
		out[U32ToAddr(u32At(row, 16))] = mac
	}
	return out
}

// u32At reads a DWORD that iphlpapi stores in network byte order (addresses and
// netmasks) and returns it in canonical numeric order.
func u32At(p unsafe.Pointer, off uintptr) uint32 {
	b := unsafe.Slice((*byte)(unsafe.Add(p, off)), 4)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// U32ToAddr converts a host-order uint32 to an IPv4 address.
func U32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// AddrToU32 converts an IPv4 address to a host-order uint32.
func AddrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// IsLoopbackTarget reports whether every address maps to the loopback device.
func IsLoopbackTarget(a netip.Addr) bool { return a.IsLoopback() }

// MatchAdapter resolves a user-supplied selector ("3", "以太网", "NPF_{GUID}",
// or any substring of the friendly name/description/GUID) against the list.
func MatchAdapter(list []Adapter, sel string) (Adapter, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return Adapter{}, errors.New("未指定网卡")
	}
	// numeric index as printed by -list-if
	for _, a := range list {
		if fmt.Sprintf("%d", a.Index) == sel {
			return a, nil
		}
	}
	needle := foldSelector(sel)
	var hits []Adapter
	for _, a := range list {
		hay := foldSelector(a.Label() + " " + a.Desc + " " + a.Name + " " + a.Device)
		if hay != "" && strings.Contains(hay, needle) {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 0:
		return Adapter{}, fmt.Errorf("找不到匹配 %q 的网卡，请用 -list-if 查看可用列表", sel)
	case 1:
		return hits[0], nil
	default:
		var names []string
		for _, a := range hits {
			names = append(names, fmt.Sprintf("#%d %s", a.Index, a.Label()))
		}
		return Adapter{}, fmt.Errorf("%q 匹配到多块网卡：%s，请改用编号", sel, strings.Join(names, "，"))
	}
}

// foldSelector lowercases s and drops punctuation, keeping letters (including
// CJK) and digits, so "NPF_{GUID}" and "npf_guid" both match.
func foldSelector(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// goString reads a NUL-terminated single-byte string.
func goString(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	n := 0
	for n < 512 {
		if *(*byte)(unsafe.Add(p, uintptr(n))) == 0 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(p), n))
}

// goWide reads a NUL-terminated UTF-16LE string.
func goWide(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	n := 0
	for n < 512 {
		if *(*uint16)(unsafe.Add(p, uintptr(n)*2)) == 0 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n)
	for i := 0; i < n; i++ {
		buf[i] = *(*uint16)(unsafe.Add(p, uintptr(i)*2))
	}
	out := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		r := rune(buf[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < n {
			if r2 := rune(buf[i+1]); r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
				i++
			}
		}
		out = append(out, r)
	}
	return string(out)
}
