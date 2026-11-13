package scan

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"goport/internal/enc"
)

func sampleResult() Result {
	return Result{
		Host:    "10.0.0.9",
		Port:    443,
		Proto:   "tcp",
		State:   StateOpen.String(),
		Service: "https",
		Banner:  "TLS 1.3 CN=example.com",
		RTT:     1500 * time.Microsecond,
	}
}

func TestSinkTable(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatTable, false)
	s.Emit(sampleResult())
	s.Emit(Result{Host: "10.0.0.9", Port: 81, Proto: "tcp", State: StateClosed.String(), RTT: 2 * time.Millisecond})
	if s.Count() != 2 {
		t.Errorf("Count = %d", s.Count())
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("table has %d lines, want 3 (header + 2 rows): %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "HOST") || !strings.Contains(lines[0], "STATE") {
		t.Errorf("header = %q", lines[0])
	}
	if !strings.Contains(lines[1], "10.0.0.9") || !strings.Contains(lines[1], "443") ||
		!strings.Contains(lines[1], "open") || !strings.Contains(lines[1], "1.5ms") ||
		!strings.Contains(lines[1], "example.com") {
		t.Errorf("row = %q", lines[1])
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color codes leaked into a non-color sink")
	}
	// Columns must line up: every row starts the port column at the same offset.
	if strings.Index(lines[1], "443") != strings.Index(lines[2], "81") {
		t.Errorf("port column is not aligned:\n%s\n%s", lines[1], lines[2])
	}
}

func TestSinkTableColor(t *testing.T) {
	// Stripping the colour codes must reproduce the plain table byte for byte,
	// which proves the escapes never shift the column alignment.
	rows := []Result{
		sampleResult(),
		{Host: "10.0.0.9", Port: 81, Proto: "tcp", State: StateClosed.String(), RTT: 2 * time.Millisecond},
		{Host: "10.0.0.10", Port: 65535, Proto: "udp", State: StateOpenFiltered.String(), Service: "x"},
	}
	var plain, colored bytes.Buffer
	p := NewSink(&plain, FormatTable, false)
	c := NewSink(&colored, FormatTable, true)
	for _, r := range rows {
		p.Emit(r)
		c.Emit(r)
	}
	if !strings.Contains(colored.String(), ansiGreen) || !strings.Contains(colored.String(), ansiYellow) {
		t.Errorf("expected coloured states, got %q", colored.String())
	}
	if got, want := stripANSI(colored.String()), plain.String(); got != want {
		t.Errorf("colour escapes changed the layout:\ncoloured/stripped:\n%s\nplain:\n%s", got, want)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestSinkJSON(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatJSON, false)
	s.Emit(sampleResult())
	s.Emit(Result{Host: "10.0.0.9", Port: 22, Proto: "tcp", State: StateOpen.String()})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("got %d objects", len(got))
	}
	if got[0]["host"] != "10.0.0.9" || got[0]["port"].(float64) != 443 || got[0]["state"] != "open" {
		t.Errorf("object = %v", got[0])
	}
	if _, ok := got[0]["rtt_ms"]; !ok {
		t.Error("rtt_ms missing from JSON output")
	}
	if got[0]["at"] == "" {
		t.Error("timestamp missing from JSON output")
	}
}

func TestSinkJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatJSON, false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("empty JSON sink = %q", buf.String())
	}
}

func TestSinkNDJSON(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatNDJSON, false)
	s.Emit(sampleResult())
	s.Emit(sampleResult())
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("bad NDJSON line %q: %v", line, err)
		}
	}
}

func TestSinkCSV(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatCSV, false)
	s.Emit(Result{Host: "10.0.0.9", Port: 80, Proto: "tcp", State: StateOpen.String(),
		Service: "http", Banner: "HTTP/1.1 200, \"OK\"", RTT: time.Millisecond})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v\n%s", err, buf.String())
	}
	if len(records) != 2 {
		t.Fatalf("got %d records", len(records))
	}
	if len(records[0]) != 8 || records[0][0] != "host" || records[0][7] != "at" {
		t.Errorf("header = %v", records[0])
	}
	if records[1][6] != "HTTP/1.1 200, \"OK\"" {
		t.Errorf("banner field = %q (CSV quoting broken)", records[1][6])
	}
	if records[1][1] != "80" || records[1][4] != "http" {
		t.Errorf("row = %v", records[1])
	}
}

func TestSinkCSVEmptyStillHasHeader(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatCSV, false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(records) != 1 || records[0][0] != "host" {
		t.Errorf("empty CSV sink should still write the header, got %v", records)
	}
}

func TestSinkCSVGBK(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatCSV, false)
	s.SetCSVEncoder(enc.ToGBK)
	s.Emit(Result{
		Host: "10.0.0.9", Port: 80, Proto: "tcp", State: StateOpen.String(),
		Service: "http", Banner: "HTTP/1.1 200 OK 登录页", RTT: 3 * time.Millisecond,
	})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The file must be decodable as GBK and contain the original Chinese text.
	text, err := enc.FromGBK(buf.Bytes())
	if err != nil {
		t.Fatalf("exported CSV is not valid GBK: %v", err)
	}
	if !strings.Contains(text, "登录页") {
		t.Errorf("Chinese banner lost in GBK export: %q", text)
	}
	records, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil {
		t.Fatalf("GBK CSV is not parseable after decoding: %v", err)
	}
	if len(records) != 2 || records[0][0] != "host" {
		t.Fatalf("unexpected records: %v", records)
	}
	if records[1][6] != "HTTP/1.1 200 OK 登录页" {
		t.Errorf("banner = %q", records[1][6])
	}
}

func TestSinkCSVEncoderErrorsAreRecorded(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, FormatCSV, false)
	s.SetCSVEncoder(func(string) ([]byte, error) { return nil, errBoom })
	s.Emit(sampleResult())
	if err := s.Close(); err != nil && !errors.Is(err, errBoom) {
		t.Errorf("expected the encoder error, got %v", err)
	}
}

var errBoom = errors.New("boom")

func TestParseFormat(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Format
	}{
		{"", FormatTable}, {"table", FormatTable}, {"JSON", FormatJSON},
		{"ndjson", FormatNDJSON}, {"jsonl", FormatNDJSON}, {"csv", FormatCSV},
	} {
		got, err := ParseFormat(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseFormat(%q) = %v, %v", c.in, got, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("unknown format should fail")
	}
}

func TestParseMode(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Mode
	}{
		{"", ModeAuto}, {"auto", ModeAuto}, {"A", ModeAuto},
		{"syn", ModeSYN}, {"S", ModeSYN}, {"half-open", ModeSYN},
		{"connect", ModeConnect}, {"C", ModeConnect}, {"full", ModeConnect},
	} {
		got, err := ParseMode(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseMode(%q) = %v, %v", c.in, got, err)
		}
	}
	if _, err := ParseMode("udp"); err == nil {
		t.Error("unknown mode should fail")
	}
}

func TestPadHelpers(t *testing.T) {
	if got := padRight("中文", 6); len([]rune(got)) != 6 {
		t.Errorf("padRight counted bytes, not runes: %q", got)
	}
	if got := truncateRunes("abcdef", 4); got != "abc…" {
		t.Errorf("truncateRunes = %q", got)
	}
	if got := truncateRunes("abc", 4); got != "abc" {
		t.Errorf("truncateRunes should not shorten: %q", got)
	}
	if got := orDash(""); got != "-" {
		t.Errorf("orDash = %q", got)
	}
}

func TestStateStrings(t *testing.T) {
	for _, c := range []struct {
		s    State
		want string
	}{
		{StateOpen, "open"}, {StateClosed, "closed"},
		{StateFiltered, "filtered"}, {StateOpenFiltered, "open|filtered"},
		{State(99), "unknown"},
	} {
		if got := c.s.String(); got != c.want {
			t.Errorf("State(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}
