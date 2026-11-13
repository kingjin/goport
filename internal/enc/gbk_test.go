package enc

import (
	"bytes"
	"strings"
	"testing"
)

func TestToGBKKnownBytes(t *testing.T) {
	// 中 = D6 D0, 文 = CE C4 in GBK.
	got, err := ToGBK("中文")
	if err != nil {
		t.Fatalf("ToGBK: %v", err)
	}
	want := []byte{0xD6, 0xD0, 0xCE, 0xC4}
	if !bytes.Equal(got, want) {
		t.Errorf("ToGBK(\"中文\") = % X, want % X", got, want)
	}
}

func TestToGBKASCIIUnchanged(t *testing.T) {
	const s = "host,port,state\r\n10.0.0.1,443,open\r\n"
	got, err := ToGBK(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != s {
		t.Errorf("ASCII should pass through unchanged, got %q", got)
	}
}

func TestToGBKEmpty(t *testing.T) {
	got, err := ToGBK("")
	if err != nil || len(got) != 0 {
		t.Fatalf("ToGBK(\"\") = %v, %v", got, err)
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := []string{
		"扫描记录",
		"时间,主机,端口,协议,状态,服务,耗时(ms),信息",
		"127.0.0.1,445,tcp,open,microsoft-ds,28.8,SSH-2.0-OpenSSH_8.9",
		"混合 mixed 内容，含标点：；、。！",
		"中文 + ASCII + 数字 12345",
	}
	for _, in := range inputs {
		gbk, err := ToGBK(in)
		if err != nil {
			t.Fatalf("ToGBK(%q): %v", in, err)
		}
		back, err := FromGBK(gbk)
		if err != nil {
			t.Fatalf("FromGBK(%q): %v", in, err)
		}
		if back != in {
			t.Errorf("round trip: %q -> %q", in, back)
		}
	}
}

func TestGBKIsTwoBytesForHanzi(t *testing.T) {
	gbk, err := ToGBK("端口")
	if err != nil {
		t.Fatal(err)
	}
	if len(gbk) != 4 {
		t.Errorf("two Hanzi should be 4 GBK bytes, got %d (% X)", len(gbk), gbk)
	}
	for _, b := range gbk {
		if b > 0x80 && b < 0x40 {
			t.Errorf("unexpected GBK byte %#x", b)
		}
	}
}

func TestFromGBKRejectsGarbageUTF8(t *testing.T) {
	// A lone UTF-8 encoded 中 (E4 B8 AD) is not valid GBK in general; the point
	// here is only that arbitrary bytes never panic.
	for _, b := range [][]byte{{0xFF, 0xFE, 0xFD}, {0x80}, {0xE4, 0xB8, 0xAD}} {
		_, _ = FromGBK(b)
	}
}

func TestCSVHeaderEncodesToGBK(t *testing.T) {
	header := "时间,主机,端口,协议,状态,服务,耗时(ms),信息\r\n"
	gbk, err := ToGBK(header)
	if err != nil {
		t.Fatal(err)
	}
	// The comma and CRLF are ASCII; the Chinese labels are 2 bytes each.
	if !strings.Contains(string(gbk), ",") || !bytes.Contains(gbk, []byte("\r\n")) {
		t.Error("CSV punctuation should stay ASCII in GBK output")
	}
	back, err := FromGBK(gbk)
	if err != nil || back != header {
		t.Fatalf("header round trip failed: %q, %v", back, err)
	}
}
