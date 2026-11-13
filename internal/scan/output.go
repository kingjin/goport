package scan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Format is an output format for results.
type Format string

const (
	FormatTable  Format = "table"
	FormatJSON   Format = "json"
	FormatNDJSON Format = "ndjson"
	FormatCSV    Format = "csv"
)

// ParseFormat validates a -format value.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "table", "txt", "text":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "ndjson", "jsonl":
		return FormatNDJSON, nil
	case "csv":
		return FormatCSV, nil
	}
	return "", fmt.Errorf("未知输出格式 %q（支持 table / json / ndjson / csv）", s)
}

// ANSI colours for the table output.
const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
)

var csvHeader = []string{"host", "port", "proto", "state", "service", "rtt_ms", "banner", "at"}

// Sink serialises results from the scanner's workers into one output stream.
// It is safe for concurrent use.
type Sink struct {
	mu      sync.Mutex
	w       io.Writer
	format  Format
	color   bool
	count   int
	cw      *csv.Writer
	csvEnc  func(string) ([]byte, error)
	started bool
	err     error
}

// NewSink builds a result sink writing to w.
func NewSink(w io.Writer, format Format, color bool) *Sink {
	s := &Sink{w: w, format: format, color: color}
	if format == FormatCSV {
		s.cw = csv.NewWriter(w)
	}
	return s
}

// SetCSVEncoder routes every CSV record through fn before it reaches the
// underlying writer, which is how a GBK/GB2312 CSV is produced for Excel. It
// must be called before the first result is written.
func (s *Sink) SetCSVEncoder(fn func(string) ([]byte, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csvEnc = fn
	if s.format != FormatCSV {
		return
	}
	var w io.Writer = s.w
	if fn != nil {
		w = &encodingWriter{w: s.w, fn: fn}
	}
	s.cw = csv.NewWriter(w)
}

// encodingWriter converts each complete CSV record to the target encoding.
// csv.Writer emits whole records in a single Write call, so a multi-byte
// character is never split across conversions.
type encodingWriter struct {
	w  io.Writer
	fn func(string) ([]byte, error)
}

func (e *encodingWriter) Write(p []byte) (int, error) {
	b, err := e.fn(string(p))
	if err != nil {
		return 0, err
	}
	if _, err := e.w.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Count reports how many results were written.
func (s *Sink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Emit writes one result.
func (s *Sink) Emit(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	if r.At == "" {
		r.At = time.Now().Format(time.RFC3339)
	}
	r.RTTMs = float64(r.RTT.Microseconds()) / 1000.0

	switch s.format {
	case FormatJSON:
		s.emitJSON(r)
	case FormatNDJSON:
		b, err := json.Marshal(r)
		if err != nil {
			s.err = err
			return
		}
		fmt.Fprintln(s.w, string(b))
	case FormatCSV:
		if !s.started {
			s.started = true
			_ = s.cw.Write(csvHeader)
		}
		rtt := ""
		if r.RTT > 0 {
			rtt = strconv.FormatFloat(r.RTTMs, 'f', 2, 64)
		}
		_ = s.cw.Write([]string{r.Host, strconv.Itoa(int(r.Port)), r.Proto, r.State, r.Service, rtt, r.Banner, r.At})
		s.cw.Flush()
		if err := s.cw.Error(); err != nil {
			s.err = err
		}
	default:
		s.emitTable(r)
	}
}

func (s *Sink) emitJSON(r Result) {
	if !s.started {
		fmt.Fprint(s.w, "[")
		s.started = true
	} else {
		fmt.Fprint(s.w, ",")
	}
	b, err := json.Marshal(r)
	if err != nil {
		s.err = err
		return
	}
	fmt.Fprint(s.w, "\n  "+string(b))
}

func (s *Sink) emitTable(r Result) {
	if !s.started {
		s.started = true
		header := padRight("HOST", 16) + " " + padRight("PORT", 6) + " " + padRight("PROTO", 6) + " " +
			padRight("STATE", 13) + " " + padRight("SERVICE", 14) + " " + padRight("RTT", 9) + " INFO"
		if s.color {
			fmt.Fprintln(s.w, ansiBold+header+ansiReset)
		} else {
			fmt.Fprintln(s.w, header)
		}
	}

	port := padRight(strconv.Itoa(int(r.Port)), 6)
	state := padRight(r.State, 13)
	service := padRight(truncateRunes(orDash(r.Service), 14), 14)
	rtt := padRight(rttText(r.RTT), 9)
	info := r.Banner
	if info == "" {
		info = ""
	}

	if s.color {
		port = ansiCyan + port + ansiReset
		state = stateColor(r.State) + state + ansiReset
		if info != "" {
			info = ansiDim + info + ansiReset
		}
	}
	line := padRight(r.Host, 16) + " " + port + " " + padRight(r.Proto, 6) + " " + state + " " + service + " " + rtt
	if info != "" {
		line += " " + info
	}
	fmt.Fprintln(s.w, line)
}

func stateColor(state string) string {
	switch state {
	case StateOpen.String():
		return ansiGreen
	case StateClosed.String():
		return ansiRed
	default:
		return ansiYellow
	}
}

func rttText(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%dus", d.Microseconds())
	}
}

// Close finishes the stream (closing the JSON array, flushing CSV).
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.format {
	case FormatJSON:
		if !s.started {
			fmt.Fprintln(s.w, "[]")
		} else {
			fmt.Fprintln(s.w, "\n]")
		}
	case FormatCSV:
		if !s.started {
			s.started = true
			_ = s.cw.Write(csvHeader)
		}
		s.cw.Flush()
		return s.cw.Error()
	}
	return s.err
}

// padRight pads s with spaces to width, counting runes (CJK names stay aligned).
func padRight(s string, width int) string {
	n := len([]rune(s))
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// truncateRunes shortens s to at most n runes, adding an ellipsis.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
