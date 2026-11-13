package scan

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"goport/internal/netinfo"
)

// writeFile is a small helper so tests can create fixtures without importing
// os everywhere.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func TestParseTargetsSingleAndCIDR(t *testing.T) {
	tg, err := ParseTargets([]string{"192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.Addrs) != 1 || U32String(tg.Addrs[0]) != "192.168.1.10" {
		t.Fatalf("got %v", tg.Addrs)
	}

	tg, err = ParseTargets([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	// A /24 has 256 addresses; network and broadcast are dropped.
	if len(tg.Addrs) != 254 {
		t.Fatalf("/24 expanded to %d addresses, want 254", len(tg.Addrs))
	}
	if U32String(tg.Addrs[0]) != "192.168.1.1" {
		t.Errorf("first host = %s", U32String(tg.Addrs[0]))
	}
	if U32String(tg.Addrs[len(tg.Addrs)-1]) != "192.168.1.254" {
		t.Errorf("last host = %s", U32String(tg.Addrs[len(tg.Addrs)-1]))
	}
}

func TestParseTargetsSmallPrefixes(t *testing.T) {
	for _, c := range []struct {
		cidr string
		want int
	}{
		{"10.0.0.0/30", 2}, // network + broadcast dropped
		{"10.0.0.0/31", 2}, // both usable
		{"10.0.0.7/32", 1},
	} {
		tg, err := ParseTargets([]string{c.cidr})
		if err != nil {
			t.Fatalf("%s: %v", c.cidr, err)
		}
		if len(tg.Addrs) != c.want {
			t.Errorf("%s expanded to %d, want %d", c.cidr, len(tg.Addrs), c.want)
		}
	}
}

func TestParseTargetsRanges(t *testing.T) {
	cases := []struct {
		expr  string
		first string
		last  string
		n     int
	}{
		{"10.0.0.1-3", "10.0.0.1", "10.0.0.3", 3},
		{"10.0.0.250-253", "10.0.0.250", "10.0.0.253", 4},
		{"10.0.0.1-10.0.0.4", "10.0.0.1", "10.0.0.4", 4},
		{"10.0.0.9-10.0.0.5", "10.0.0.5", "10.0.0.9", 5},
	}
	for _, c := range cases {
		tg, err := ParseTargets([]string{c.expr})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if len(tg.Addrs) != c.n {
			t.Fatalf("%s: %d addresses, want %d", c.expr, len(tg.Addrs), c.n)
		}
		if U32String(tg.Addrs[0]) != c.first || U32String(tg.Addrs[len(tg.Addrs)-1]) != c.last {
			t.Errorf("%s: got %s..%s", c.expr, U32String(tg.Addrs[0]), U32String(tg.Addrs[len(tg.Addrs)-1]))
		}
	}
}

func TestParseTargetsListAndDedupe(t *testing.T) {
	tg, err := ParseTargets([]string{"10.0.0.1,10.0.0.2 10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.Addrs) != 2 {
		t.Fatalf("got %d addresses, want 2 (deduplicated)", len(tg.Addrs))
	}
}

func TestParseTargetsFile(t *testing.T) {
	path := t.TempDir() + "/targets.txt"
	content := "# a comment\n10.0.0.1\n\n10.0.0.2  # trailing comment\n10.0.0.0/30\n"
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	tg, err := ParseTargets([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.1, 10.0.0.2, then 10.0.0.1/.2 from the /30 (both duplicates)
	if len(tg.Addrs) != 2 {
		t.Fatalf("got %d addresses: %v", len(tg.Addrs), tg.Addrs)
	}
	if _, err := ParseTargets([]string{"@" + path + ".missing"}); err == nil {
		t.Error("missing @file should fail")
	}
}

func TestParseTargetsIPv6IsRejected(t *testing.T) {
	tg, err := ParseTargets([]string{"::1"})
	if err == nil && tg != nil && len(tg.Addrs) > 0 {
		t.Errorf("IPv6 target produced %d addresses", len(tg.Addrs))
	}
	if err == nil && tg != nil && len(tg.Warnings) == 0 {
		t.Error("IPv6 target should be reported")
	}
}

func TestParseTargetsHostnameLocalhost(t *testing.T) {
	tg, err := ParseTargets([]string{"localhost"})
	if err != nil {
		t.Skipf("localhost did not resolve: %v", err)
	}
	if len(tg.Addrs) == 0 {
		t.Fatal("localhost resolved to no addresses")
	}
	found := false
	for _, a := range tg.Addrs {
		if netinfo.U32ToAddr(a) == netip.MustParseAddr("127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Errorf("localhost should include 127.0.0.1, got %v", tg.Addrs)
	}
}

func TestParseTargetsTooLarge(t *testing.T) {
	if _, err := ParseTargets([]string{"0.0.0.0/0"}); err == nil {
		t.Error("/0 should exceed the host limit")
	}
}

func TestScopeHelpers(t *testing.T) {
	ports, _ := ParsePortSpec("80,443,U:53")
	sc := &Scope{Addrs: []uint32{0x0a000001, 0x0a000002}, Ports: ports}
	if sc.HostCount() != 2 {
		t.Errorf("HostCount = %d", sc.HostCount())
	}
	if sc.Pairs() != 6 {
		t.Errorf("Pairs = %d, want 6", sc.Pairs())
	}
	if got := sc.HostString(0); got != "10.0.0.1" {
		t.Errorf("HostString = %q", got)
	}
}

func TestU32String(t *testing.T) {
	if got := U32String(0xc0a80101); got != "192.168.1.1" {
		t.Errorf("U32String = %q", got)
	}
}

func netinfoU32(v uint32) netip.Addr { return netinfo.U32ToAddr(v) }

// TestParseTargetsPreservesOrder guards the scan order contract: CIDR order is
// preserved so progress reporting stays predictable.
func TestParseTargetsPreservesOrder(t *testing.T) {
	tg, err := ParseTargets([]string{"10.0.0.2,10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.2", "10.0.0.1"}
	var got []string
	for _, a := range tg.Addrs {
		got = append(got, U32String(a))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}
