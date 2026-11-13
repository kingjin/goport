package scan

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// tlsPorts are probed with a TLS handshake first; httpPorts with an HTTP request;
// every other port is treated as a "server speaks first" protocol and falls back
// to a small protocol-specific nudge.
var tlsPorts = map[uint16]bool{
	443: true, 465: true, 636: true, 853: true, 993: true, 995: true,
	5986: true, 6443: true, 8443: true, 9443: true, 9444: true, 10443: true,
	8444: true, 9447: true, 8883: true, 19900: true,
}

var httpPorts = map[uint16]bool{
	80: true, 81: true, 82: true, 83: true, 84: true, 88: true, 591: true, 593: true,
	1080: true, 2082: true, 2083: true, 3000: true, 3128: true, 4000: true, 5000: true,
	5601: true, 6080: true, 7001: true, 7002: true, 7443: true, 8000: true, 8001: true,
	8008: true, 8009: true, 8010: true, 8020: true, 8032: true, 8042: true, 8069: true,
	8080: true, 8081: true, 8082: true, 8083: true, 8085: true, 8086: true, 8088: true,
	8090: true, 8091: true, 8098: true, 8161: true, 8180: true, 8200: true, 8300: true,
	8333: true, 8484: true, 8500: true, 8530: true, 8545: true, 8686: true, 8834: true,
	8880: true, 8888: true, 8899: true, 8983: true, 9000: true, 9001: true, 9042: true,
	9060: true, 9080: true, 9090: true, 9200: true, 10000: true, 11211: true,
	15672: true, 18080: true, 28017: true, 50000: true, 50070: true, 50013: true,
}

// enrichBanner fills Result.Banner/Service for an open TCP port. Failures are
// silent: a port without a banner is still a valid finding.
func enrichBanner(r *Result, timeout time.Duration) {
	if r.State != StateOpen.String() || r.Proto != "tcp" {
		return
	}
	info, service := probeBanner(r.Host, r.Port, timeout)
	if info != "" {
		r.Banner = info
	}
	if service != "" {
		r.Service = service
	}
}

// probeBanner performs the protocol-aware banner grab.
func probeBanner(host string, port uint16, timeout time.Duration) (info, service string) {
	switch {
	case tlsPorts[port]:
		if info, service = grabTLS(host, port, timeout, httpPorts[port]); info != "" || service != "" {
			return info, service
		}
		return grabPlain(host, port, timeout, nil)
	case httpPorts[port]:
		if info, service = grabHTTP(host, port, timeout); info != "" {
			return info, service
		}
		// Some "web" ports are actually TLS; try a handshake as a fallback.
		return grabTLS(host, port, timeout, false)
	}
	if payload := plainProbe(port); payload != nil {
		if info, svc := grabPlain(host, port, timeout, payload); info != "" {
			return info, svc
		}
		return "", ""
	}
	if info, svc := grabPlain(host, port, timeout, nil); info != "" {
		return info, svc
	}
	// Many services hide on non-standard ports; a plain HTTP GET is the
	// cheapest way to identify them.
	if info, svc := grabHTTP(host, port, timeout); strings.HasPrefix(info, "HTTP/") {
		return info, svc
	}
	return "", ""
}

// plainProbe returns a small nudge for protocols where the client speaks first.
func plainProbe(port uint16) []byte {
	switch port {
	case 6379:
		return []byte("PING\r\n")
	case 11211:
		return []byte("version\r\n")
	case 23:
		return []byte("\r\n")
	case 21:
		return []byte("SYST\r\n")
	case 25, 587, 465:
		return []byte("EHLO goport\r\n")
	case 110:
		return []byte("CAPA\r\n")
	case 119:
		return []byte("HELP\r\n")
	case 1433:
		// a bare TDS pre-login packet is enough for some SQL Server builds
		return []byte{0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00}
	}
	return nil
}

// grabPlain reads a server-first banner, optionally after sending a probe.
func grabPlain(host string, port uint16, timeout time.Duration, payload []byte) (string, string) {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		_, _ = conn.Write(payload)
	}
	// Cap the wait for the first byte: a silent protocol (SMB, RDP, ...) would
	// otherwise burn the whole timeout for nothing.
	firstByte := timeout
	if firstByte > 700*time.Millisecond {
		firstByte = 700 * time.Millisecond
	}
	data := readSome(conn, 2048, firstByte)
	if len(data) == 0 {
		return "", ""
	}
	return describePayload(data, port)
}

// grabHTTP issues a minimal GET request and extracts status, server and title.
func grabHTTP(host string, port uint16, timeout time.Duration) (string, string) {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: goport/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, port)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", ""
	}
	data := readSome(conn, 4096, timeout)
	if len(data) == 0 {
		return "", ""
	}
	return describePayload(data, port)
}

// grabTLS completes a TLS handshake and reports the certificate, plus the HTTP
// banner when the service behind it speaks HTTP.
func grabTLS(host string, port uint16, timeout time.Duration, tryHTTP bool) (string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), &tls.Config{
		InsecureSkipVerify: true, // a scanner must not fail on bad certificates
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var parts []string
	// tls.VersionName already includes the "TLS" prefix.
	parts = append(parts, tls.VersionName(state.Version))
	if c := state.PeerCertificates; len(c) > 0 {
		leaf := c[0]
		cn := leaf.Subject.CommonName
		if cn == "" && len(leaf.DNSNames) > 0 {
			cn = leaf.DNSNames[0]
		}
		if cn != "" {
			parts = append(parts, "CN="+sanitize(cn, 64))
		}
		if iss := leaf.Issuer.CommonName; iss != "" {
			parts = append(parts, "issuer="+sanitize(iss, 48))
		}
		if !leaf.NotAfter.IsZero() {
			parts = append(parts, "until="+leaf.NotAfter.Format("2006-01-02"))
		}
	}
	info := strings.Join(parts, " ")
	service := "https"

	if tryHTTP {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: goport/1.0\r\nConnection: close\r\n\r\n", host)
		if _, err := conn.Write([]byte(req)); err == nil {
			if data := readSome(conn, 3072, timeout); len(data) > 0 {
				if extra, svc := describePayload(data, port); extra != "" {
					info += " | " + extra
					if svc != "" {
						service = svc
					}
				}
			}
		}
	}
	return info, service
}

// describePayload turns raw protocol bytes into a one-line description.
func describePayload(data []byte, port uint16) (string, string) {
	text := string(data)

	// HTTP
	if strings.HasPrefix(text, "HTTP/") || strings.Contains(text[:min(len(text), 512)], "HTTP/1.") {
		return describeHTTP(text), "http"
	}
	// SSH
	if strings.HasPrefix(text, "SSH-") {
		line := firstLine(text)
		return line, "ssh"
	}
	// MySQL / MariaDB handshake: 3-byte length, sequence id, protocol 0x0a
	if len(data) > 5 && data[3] == 0x00 && data[4] == 0x0a {
		v := cString(data[5:])
		if v != "" {
			return "MySQL " + v, "mysql"
		}
	}
	// Redis inline replies
	if len(text) > 0 && (text[0] == '+' || text[0] == '-' || text[0] == '*' || text[0] == '$' || text[0] == '#') {
		line := firstLine(text)
		svc := "redis"
		if strings.Contains(line, "PONG") || strings.Contains(line, "NOAUTH") || strings.Contains(line, "WRONGPASS") {
			svc = "redis"
		}
		return line, svc
	}
	// FTP/SMTP/POP3/IMAP all answer with a numeric code line
	if len(text) >= 3 && isDigits(text[:3]) {
		line := firstLine(text)
		svc := ""
		switch {
		case port == 21 || strings.Contains(strings.ToUpper(line), "FTP"):
			svc = "ftp"
		case port == 25 || port == 587 || strings.Contains(strings.ToUpper(line), "SMTP"):
			svc = "smtp"
		case port == 110 || strings.Contains(strings.ToUpper(line), "POP3"):
			svc = "pop3"
		case port == 143 || strings.Contains(strings.ToUpper(line), "IMAP"):
			svc = "imap"
		}
		return line, svc
	}
	// VNC servers announce their protocol version first
	if strings.HasPrefix(text, "RFB ") {
		return firstLine(text), "vnc"
	}
	return sanitize(text, 120), ""
}

// describeHTTP extracts status line, Server/X-Powered-By and the page title.
func describeHTTP(text string) string {
	var parts []string
	rest := text
	if i := strings.Index(text, "\r\n"); i > 0 {
		parts = append(parts, strings.TrimSpace(text[:i]))
		rest = text[i+2:]
	}
	headerEnd := strings.Index(rest, "\r\n\r\n")
	header := rest
	body := ""
	if headerEnd >= 0 {
		header = rest[:headerEnd]
		body = rest[headerEnd+4:]
	} else if i := strings.Index(rest, "\n\n"); i >= 0 {
		header = rest[:i]
		body = rest[i+2:]
	}
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") || strings.HasPrefix(lower, "x-powered-by:") {
			parts = append(parts, sanitize(line, 80))
		}
		if len(parts) >= 3 {
			break
		}
	}
	if title := extractTitle(body); title != "" {
		parts = append(parts, "title="+title)
	}
	return sanitize(strings.Join(parts, " | "), 160)
}

// extractTitle pulls the first <title> out of an HTML body.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	gt := strings.Index(body[start:], ">")
	if gt < 0 {
		return ""
	}
	start += gt + 1
	end := strings.Index(strings.ToLower(body[start:]), "</title>")
	if end < 0 {
		end = min(len(body)-start, 80)
	}
	if end <= 0 {
		return ""
	}
	return strings.TrimSpace(sanitize(body[start:start+end], 80))
}

// readSome reads up to max bytes, stopping early once data stops arriving.
func readSome(conn net.Conn, max int, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, max)
	n, err := io.ReadAtLeast(conn, buf, 1)
	if n == 0 && err != nil {
		return nil
	}
	// Drain whatever else is buffered, without waiting for a full timeout again.
	_ = conn.SetReadDeadline(time.Now().Add(minDuration(timeout/3, 300*time.Millisecond)))
	for n < max {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	return buf[:n]
}

func dialTCP(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// sanitize keeps printable ASCII, collapses whitespace and caps the length.
func sanitize(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || r == ' ':
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		case r < 0x20 || r == 0x7f:
			// drop other control bytes
		default:
			b.WriteRune(r)
			lastSpace = false
		}
		if b.Len() >= max*4 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > max {
		out = out[:max] + "…"
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return sanitize(s, 120)
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}
