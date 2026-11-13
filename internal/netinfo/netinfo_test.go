package netinfo

import (
	"net/netip"
	"strings"
	"testing"
)

func TestMaskBits(t *testing.T) {
	for _, c := range []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
		{"255.255.255.128", 25},
		{"255.255.224.0", 19},
	} {
		if got := MaskBits(netip.MustParseAddr(c.mask)); got != c.want {
			t.Errorf("MaskBits(%s) = %d, want %d", c.mask, got, c.want)
		}
	}
}

func TestAddrU32RoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "1.2.3.4", "10.108.112.112", "255.255.255.255"} {
		a := netip.MustParseAddr(s)
		v := AddrToU32(a)
		if got := U32ToAddr(v); got != a {
			t.Errorf("%s -> %#x -> %s", a, v, got)
		}
	}
	if got := AddrToU32(netip.MustParseAddr("192.168.1.1")); got != 0xc0a80101 {
		t.Errorf("AddrToU32 = %#x", got)
	}
}

func TestAdapterHelpers(t *testing.T) {
	a := Adapter{
		Index:    6,
		Name:     "{3C31DD2F-437B-4AE7-AC6A-007DFBF5C4BA}",
		Desc:     "Intel(R) Wi-Fi 6 AX200 160MHz",
		Friendly: "WLAN",
		MAC:      []byte{0xb0, 0xa4, 0x60, 0xc0, 0x05, 0x71},
		Up:       true,
		IPv4:     []netip.Addr{netip.MustParseAddr("10.108.112.112")},
		Masks:    []netip.Addr{netip.MustParseAddr("255.255.255.0")},
		Device:   `\Device\NPF_{3C31DD2F-437B-4AE7-AC6A-007DFBF5C4BA}`,
	}
	if got := a.MACString(); got != "b0:a4:60:c0:05:71" {
		t.Errorf("MACString = %q", got)
	}
	p, ok := a.Prefix()
	if !ok || p.String() != "10.108.112.112/24" {
		t.Errorf("Prefix = %v, %v", p, ok)
	}
	mac, ok := a.MAC6()
	if !ok || mac[0] != 0xb0 || mac[5] != 0x71 {
		t.Errorf("MAC6 = %v, %v", mac, ok)
	}
	row := a.String()
	if !strings.Contains(row, "#6") || !strings.Contains(row, "10.108.112.112/24") || !strings.Contains(row, "up") {
		t.Errorf("String = %q", row)
	}
	if !strings.Contains(row, "WLAN") {
		t.Errorf("String should use the friendly name: %q", row)
	}

	// Missing MAC and address data must degrade gracefully.
	empty := Adapter{Friendly: "x"}
	if empty.MACString() != "-" {
		t.Errorf("empty MACString = %q", empty.MACString())
	}
	if _, ok := empty.MAC6(); ok {
		t.Error("empty adapter should not report a MAC")
	}
	if _, ok := empty.Prefix(); ok {
		t.Error("empty adapter should not report a prefix")
	}
}

func TestMatchAdapter(t *testing.T) {
	list := []Adapter{
		{Index: 6, Friendly: "WLAN", Desc: "Intel Wi-Fi 6", Name: "{AAAA}", Device: `\Device\NPF_{AAAA}`},
		{Index: 16, Friendly: "以太网", Desc: "Realtek GbE", Name: "{BBBB}", Device: `\Device\NPF_{BBBB}`},
		{Index: 1, Friendly: "Loopback", Desc: "Npcap Loopback Adapter", Name: "Loopback", Device: `\Device\NPF_Loopback`},
	}
	for _, c := range []struct {
		sel  string
		want uint32
	}{
		{"6", 6},
		{"16", 16},
		{"WLAN", 6},
		{"wlan", 6},
		{"以太网", 16},
		{"Realtek", 16},
		{"{BBBB}", 16},
		{"NPF_AAAA", 6},
		{"loopback", 1},
	} {
		got, err := MatchAdapter(list, c.sel)
		if err != nil {
			t.Errorf("MatchAdapter(%q): %v", c.sel, err)
			continue
		}
		if got.Index != c.want {
			t.Errorf("MatchAdapter(%q) = #%d, want #%d", c.sel, got.Index, c.want)
		}
	}

	if _, err := MatchAdapter(list, "nope"); err == nil {
		t.Error("unknown selector should fail")
	}
	if _, err := MatchAdapter(list, ""); err == nil {
		t.Error("empty selector should fail")
	}
	// "loopback" appears in the friendly name and the description, and a
	// two-adapter match must be reported instead of guessed.
	amb := append(list, Adapter{Index: 9, Friendly: "loopback 2", Desc: "second loopback"})
	if _, err := MatchAdapter(amb, "loopback"); err == nil ||
		!strings.Contains(err.Error(), "多块网卡") {
		t.Errorf("ambiguous selector should list the candidates, got %v", err)
	}
}

func TestLoopbackAdapter(t *testing.T) {
	lo := LoopbackAdapter()
	if lo.Device != `\Device\NPF_Loopback` {
		t.Errorf("Device = %q", lo.Device)
	}
	if p, ok := lo.Prefix(); !ok || p.String() != "127.0.0.1/8" {
		t.Errorf("Prefix = %v, %v", p, ok)
	}
}

func TestAdaptersEnumerate(t *testing.T) {
	ads, err := Adapters()
	if err != nil {
		t.Skipf("no adapters available: %v", err)
	}
	if len(ads) == 0 {
		t.Skip("adapter list is empty")
	}
	for _, a := range ads {
		if a.Device != "" && !strings.HasPrefix(a.Device, `\Device\NPF_`) {
			t.Errorf("adapter %d device name %q is not an NPF path", a.Index, a.Device)
		}
		if len(a.IPv4) != len(a.Masks) {
			t.Errorf("adapter %d has %d addresses but %d masks", a.Index, len(a.IPv4), len(a.Masks))
		}
		for _, ip := range a.IPv4 {
			if !ip.Is4() {
				t.Errorf("adapter %d returned a non-IPv4 address %v", a.Index, ip)
			}
		}
	}
}

func TestDefaultRouteIsSane(t *testing.T) {
	idx, gw, ok := DefaultRoute()
	if !ok {
		t.Skip("no default route on this host")
	}
	if idx == 0 {
		t.Error("default route has interface index 0")
	}
	if !gw.Is4() || gw.IsUnspecified() {
		t.Errorf("default route gateway = %v", gw)
	}
}

func TestARPCacheEntries(t *testing.T) {
	cache := ARPCache()
	for ip, mac := range cache {
		if !ip.Is4() {
			t.Errorf("ARP cache contains a non-IPv4 key %v", ip)
		}
		if mac == [6]byte{} || mac == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
			t.Errorf("ARP cache contains a junk entry %v -> %v", ip, mac)
		}
	}
}

func TestRouteTo(t *testing.T) {
	if _, ok := RouteTo(netip.MustParseAddr("10.108.112.1")); !ok {
		t.Skip("no matching route on this host")
	}
	r, ok := RouteTo(netip.MustParseAddr("10.108.112.1"))
	if !ok {
		t.Fatal("RouteTo returned no route for a local address")
	}
	if r.IfIndex == 0 {
		t.Error("route has no interface index")
	}
}
