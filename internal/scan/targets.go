package scan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// MaxHosts caps a single scan so a typo like 0.0.0.0/0 cannot exhaust memory.
const MaxHosts = 1 << 24 // 16,777,216 addresses

// Scope is the fully resolved set of addresses and ports to probe.
type Scope struct {
	Addrs []uint32 // IPv4 addresses in host order, scan order
	Ports PortSet
}

// HostCount returns the number of addresses.
func (s *Scope) HostCount() int { return len(s.Addrs) }

// Pairs is the number of host/port probes (TCP and UDP combined).
func (s *Scope) Pairs() int { return len(s.Addrs) * s.Ports.Total() }

// HostString renders the i-th address.
func (s *Scope) HostString(i int) string { return U32String(s.Addrs[i]) }

// U32String formats a host-order IPv4 value.
func U32String(v uint32) string {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

// Targeting accumulates the target list and any non-fatal resolution warnings.
type Targeting struct {
	Addrs    []uint32
	Warnings []string
	Sources  []string
}

// Warning returns any resolution warnings accumulated while parsing.
func (t *Targeting) WarningsOrNil() []string {
	if t == nil {
		return nil
	}
	return t.Warnings
}

// ParseTargets expands every target expression into addresses.
//
// Accepted forms (comma or whitespace separated, repeatable):
//
//	192.168.1.10              single address
//	192.168.1.0/24            CIDR block
//	192.168.1.1-254           range on the last octet
//	192.168.1.1-192.168.1.9   arbitrary range
//	example.com               host name (all A records)
//	hosts.txt  or  @hosts.txt file with one expression per line (# comments)
func ParseTargets(items []string) (*Targeting, error) {
	t := &Targeting{}
	seen := make(map[uint32]struct{})
	dedupe := true

	addAddr := func(v uint32) {
		if len(t.Addrs) >= MaxHosts {
			return
		}
		if dedupe {
			if _, dup := seen[v]; dup {
				return
			}
			seen[v] = struct{}{}
		}
		t.Addrs = append(t.Addrs, v)
	}

	var expressions []string
	for _, item := range items {
		for _, expr := range expandItem(item, &t.Warnings) {
			expressions = append(expressions, expr)
		}
	}
	if len(expressions) == 0 {
		return nil, fmt.Errorf("没有解析到任何目标")
	}
	// A huge scope would make the dedupe map the dominant memory cost.
	if len(expressions) > 1<<12 {
		dedupe = false
	}

	for _, expr := range expressions {
		addrs, err := parseTargetExpr(expr)
		if err != nil {
			t.Warnings = append(t.Warnings, err.Error())
			continue
		}
		if len(t.Addrs)+len(addrs) > MaxHosts {
			return nil, fmt.Errorf("目标数量超过上限 %d（当前 %d）", MaxHosts, len(t.Addrs)+len(addrs))
		}
		for _, a := range addrs {
			addAddr(a)
		}
		t.Sources = append(t.Sources, expr)
	}
	if len(t.Addrs) == 0 {
		return nil, fmt.Errorf("没有可扫描的地址")
	}
	return t, nil
}

// expandItem splits one CLI argument into expressions, reading files.
func expandItem(item string, warnings *[]string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return nil
	}
	path := item
	fromFile := strings.HasPrefix(item, "@")
	if fromFile {
		path = item[1:]
	} else {
		// Treat as a file only when it exists and is not a bare IP/CIDR.
		if !looksLikeExpr(item) {
			if st, err := os.Stat(item); err != nil || st.IsDir() {
				path = ""
			}
		} else {
			path = ""
		}
	}
	if path != "" {
		lines, err := readTargetFile(path)
		if err != nil {
			*warnings = append(*warnings, err.Error())
			return nil
		}
		return lines
	}
	var out []string
	for _, part := range splitList(item) {
		out = append(out, part)
	}
	return out
}

func looksLikeExpr(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if strings.Contains(s, "-") && strings.Count(s, ".") == 3 {
		return true
	}
	return false
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读取目标文件 %s 失败：%w", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, splitList(line)...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取目标文件 %s 失败：%w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("目标文件 %s 中没有有效地址", path)
	}
	return out, nil
}

// parseTargetExpr expands a single expression into addresses.
func parseTargetExpr(expr string) ([]uint32, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	if prefix, err := netip.ParsePrefix(expr); err == nil {
		return expandPrefix(prefix)
	}
	if addr, err := netip.ParseAddr(expr); err == nil {
		addr = addr.Unmap()
		if !addr.Is4() {
			return nil, fmt.Errorf("%s：暂不支持 IPv6（GoPort 目前只做 IPv4 原始探测）", expr)
		}
		b := addr.As4()
		return []uint32{be32(b)}, nil
	}
	if lo, hi, ok := parseAddrRange(expr); ok {
		if hi < lo {
			lo, hi = hi, lo
		}
		if uint64(hi)-uint64(lo)+1 > MaxHosts {
			return nil, fmt.Errorf("%s：范围过大（%d 个地址）", expr, uint64(hi)-uint64(lo)+1)
		}
		out := make([]uint32, 0, hi-lo+1)
		for v := lo; v <= hi; v++ {
			out = append(out, v)
			if v == 0xffffffff {
				break
			}
		}
		return out, nil
	}
	// Fall back to a DNS lookup for host names.
	addrs, err := lookupHost(expr)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func expandPrefix(prefix netip.Prefix) ([]uint32, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("%s：暂不支持 IPv6", prefix)
	}
	bits := prefix.Bits()
	count := uint64(1) << uint(32-bits)
	if count > MaxHosts {
		return nil, fmt.Errorf("%s 包含 %d 个地址，超过单次扫描上限 %d", prefix, count, MaxHosts)
	}
	base := be32(prefix.Addr().Unmap().As4())
	out := make([]uint32, 0, count)
	for i := uint64(0); i < count; i++ {
		out = append(out, base+uint32(i))
	}
	// For a normal subnet, skip the network and broadcast addresses: no host
	// lives there. /31 and /32 are kept because both addresses are usable.
	if bits <= 30 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// parseAddrRange accepts "10.0.0.1-254" and "10.0.0.1-10.0.0.9".
func parseAddrRange(expr string) (uint32, uint32, bool) {
	i := strings.IndexByte(expr, '-')
	if i <= 0 || i == len(expr)-1 {
		return 0, 0, false
	}
	head, tail := strings.TrimSpace(expr[:i]), strings.TrimSpace(expr[i+1:])
	startAddr, err := netip.ParseAddr(head)
	if err != nil || !startAddr.Unmap().Is4() {
		return 0, 0, false
	}
	start := be32(startAddr.Unmap().As4())
	if endAddr, err := netip.ParseAddr(tail); err == nil {
		if !endAddr.Unmap().Is4() {
			return 0, 0, false
		}
		return start, be32(endAddr.Unmap().As4()), true
	}
	// Short form: the tail is the last octet.
	last, err := strconv.Atoi(tail)
	if err != nil || last < 0 || last > 255 {
		return 0, 0, false
	}
	end := (start & 0xffffff00) | uint32(last)
	return start, end, true
}

func lookupHost(name string) ([]uint32, error) {
	// "" or a URL-looking string is almost certainly a mistake.
	if strings.ContainsAny(name, "/\\") {
		return nil, fmt.Errorf("%q 既不是 IP、网段、范围，也不是可解析的主机名", name)
	}
	resolver := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("解析主机名 %s 超时", name)
		}
		return nil, fmt.Errorf("解析主机名 %s 失败：%w", name, err)
	}
	var out []uint32
	for _, ip := range ips {
		if v4 := ip.Unmap().As4(); ip.Unmap().Is4() {
			out = append(out, be32(v4))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("主机名 %s 没有 A 记录", name)
	}
	return out, nil
}

func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
