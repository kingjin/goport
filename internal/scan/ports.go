package scan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PortSet is a parsed port specification split by transport protocol.
type PortSet struct {
	TCP []uint16
	UDP []uint16
}

// Total is the number of ports to probe.
func (p PortSet) Total() int { return len(p.TCP) + len(p.UDP) }

// String renders the specification back in a compact, Goby-compatible form.
func (p PortSet) String() string {
	var parts []string
	parts = append(parts, rangesOf(p.TCP)...)
	up := rangesOf(p.UDP)
	for _, u := range up {
		parts = append(parts, "U:"+u)
	}
	return strings.Join(parts, ",")
}

func rangesOf(ports []uint16) []string {
	if len(ports) == 0 {
		return nil
	}
	sorted := append([]uint16(nil), ports...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var out []string
	start, prev := sorted[0], sorted[0]
	flush := func() {
		if start == prev {
			out = append(out, strconv.Itoa(int(start)))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, p := range sorted[1:] {
		if p == prev || p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	return out
}

// ParsePortSpec parses a Goby-compatible port list such as
// "21,22,80,U:137,443,8000-8100,all".
//
// Tokens are comma or whitespace separated. A leading "U:"/"udp:" marks a UDP
// port, an optional "T:"/"tcp:" marks TCP (the default).
func ParsePortSpec(spec string) (PortSet, error) {
	var set PortSet
	var tcp, udp []uint16

	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	})
	if len(fields) == 0 {
		return set, fmt.Errorf("端口列表为空")
	}
	for _, raw := range fields {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		isUDP := false
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "u:") || strings.HasPrefix(lower, "udp:"):
			isUDP = true
			token = token[strings.Index(token, ":")+1:]
		case strings.HasPrefix(lower, "t:") || strings.HasPrefix(lower, "tcp:"):
			token = token[strings.Index(token, ":")+1:]
		}
		if strings.EqualFold(token, "all") {
			token = "0-65535"
		}
		lo, hi, err := parsePortRange(token)
		if err != nil {
			return set, err
		}
		for p := lo; p <= hi; p++ {
			if isUDP {
				udp = append(udp, uint16(p))
			} else {
				tcp = append(tcp, uint16(p))
			}
		}
	}
	set.TCP = dedupePorts(tcp)
	set.UDP = dedupePorts(udp)
	if set.Total() == 0 {
		return set, fmt.Errorf("端口列表为空")
	}
	return set, nil
}

func parsePortRange(token string) (int, int, error) {
	if i := strings.IndexByte(token, '-'); i >= 0 && i < len(token)-1 {
		lo, err := parsePort(token[:i])
		if err != nil {
			return 0, 0, err
		}
		hi, err := parsePort(token[i+1:])
		if err != nil {
			return 0, 0, err
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		return lo, hi, nil
	}
	p, err := parsePort(token)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("端口 %q 不是数字", s)
	}
	if v < 0 || v > 65535 {
		return 0, fmt.Errorf("端口 %d 超出 0-65535", v)
	}
	return v, nil
}

func dedupePorts(in []uint16) []uint16 {
	if len(in) == 0 {
		return nil
	}
	seen := make([]bool, 65536)
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
