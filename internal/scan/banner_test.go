package scan

import (
	"strings"
	"testing"
	"time"
)

func TestDescribeHTTP(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"X-Powered-By: PHP/8.2\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<html><head><title>登录 - 后台</title></head><body>hi</body></html>"
	info, svc := describePayload([]byte(raw), 8080)
	if svc != "http" {
		t.Errorf("service = %q, want http", svc)
	}
	for _, want := range []string{"HTTP/1.1 200 OK", "nginx/1.24.0", "PHP/8.2", "title=登录 - 后台"} {
		if !strings.Contains(info, want) {
			t.Errorf("info %q missing %q", info, want)
		}
	}
}

func TestDescribeSSH(t *testing.T) {
	info, svc := describePayload([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"), 22)
	if svc != "ssh" {
		t.Errorf("service = %q", svc)
	}
	if !strings.HasPrefix(info, "SSH-2.0-OpenSSH_8.9p1") {
		t.Errorf("info = %q", info)
	}
}

func TestDescribeMySQL(t *testing.T) {
	// 3-byte length, sequence 0, protocol version 10, then the version string
	raw := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', '4', 0x00}
	info, svc := describePayload(raw, 3306)
	if svc != "mysql" {
		t.Errorf("service = %q, want mysql", svc)
	}
	if info != "MySQL 8.0.34" {
		t.Errorf("info = %q", info)
	}
}

func TestDescribeRedis(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{"+PONG\r\n", "+PONG"},
		{"-NOAUTH Authentication required.\r\n", "-NOAUTH Authentication required."},
	} {
		info, svc := describePayload([]byte(c.raw), 6379)
		if svc != "redis" {
			t.Errorf("%q: service = %q", c.raw, svc)
		}
		if info != c.want {
			t.Errorf("%q: info = %q, want %q", c.raw, info, c.want)
		}
	}
}

func TestDescribeFTPAndSMTP(t *testing.T) {
	info, svc := describePayload([]byte("220 Microsoft FTP Service\r\n"), 21)
	if svc != "ftp" || !strings.Contains(info, "220") {
		t.Errorf("ftp: info=%q svc=%q", info, svc)
	}
	info, svc = describePayload([]byte("220 mail.example.com ESMTP Postfix\r\n"), 25)
	if svc != "smtp" || !strings.Contains(info, "ESMTP") {
		t.Errorf("smtp: info=%q svc=%q", info, svc)
	}
}

func TestDescribeVNC(t *testing.T) {
	info, svc := describePayload([]byte("RFB 003.008\n"), 5900)
	if svc != "vnc" || !strings.HasPrefix(info, "RFB 003.008") {
		t.Errorf("vnc: info=%q svc=%q", info, svc)
	}
}

func TestDescribePayloadBinaryJunk(t *testing.T) {
	// Binary noise must be sanitised, not passed through raw.
	info, _ := describePayload([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 'o', 'k'}, 9999)
	for _, r := range info {
		if r < 0x20 && r != ' ' {
			t.Errorf("control rune %#x leaked into %q", r, info)
		}
	}
	if !strings.Contains(info, "ok") {
		t.Errorf("printable bytes lost: %q", info)
	}
}

func TestSanitize(t *testing.T) {
	in := "  a\r\n\tb   c  \x00\x01 d  "
	if got := sanitize(in, 100); got != "a b c d" {
		t.Errorf("sanitize = %q", got)
	}
	long := strings.Repeat("x", 200)
	if got := sanitize(long, 10); len([]rune(got)) != 11 { // 10 chars + ellipsis
		t.Errorf("sanitize truncation gave %d runes: %q", len([]rune(got)), got)
	}
	if got := sanitize("", 10); got != "" {
		t.Errorf("empty sanitize = %q", got)
	}
}

func TestExtractTitle(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{"<html><title>Hello</title></html>", "Hello"},
		{"<TITLE>Upper</TITLE>", "Upper"},
		{"<title></title>", ""},
		{"no title here", ""},
		{"<html><head><title>  spaced  </title>", "spaced"},
	} {
		if got := extractTitle(c.body); got != c.want {
			t.Errorf("extractTitle(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("abc\r\ndef"); got != "abc" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine("only"); got != "only" {
		t.Errorf("firstLine = %q", got)
	}
}

func TestFormatRTT(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{1500 * time.Microsecond, "1.5ms"},
		{20 * time.Microsecond, "20us"},
		{2 * time.Second, "2.00s"},
		{0, "-"},
	} {
		if got := rttText(c.d); got != c.want {
			t.Errorf("rttText(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestServiceNames(t *testing.T) {
	for port, want := range map[uint16]string{
		22: "ssh", 443: "https", 3306: "mysql", 6379: "redis", 3389: "ms-wbt-server",
	} {
		if got := ServiceName(port); got != want {
			t.Errorf("ServiceName(%d) = %q, want %q", port, got, want)
		}
	}
	if got := ServiceName(64999); got != "" {
		t.Errorf("unknown port returned %q", got)
	}
}
