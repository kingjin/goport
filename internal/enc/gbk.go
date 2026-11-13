// Package enc converts text between UTF-8 and the Windows ANSI code page 936
// (GBK, a superset of GB2312).
//
// The Go standard library has no GBK codec, and pulling in golang.org/x/text
// would break the "no third-party dependency, CGO_ENABLED=0" property of this
// project. Windows itself ships the conversion tables, so we call
// WideCharToMultiByte / MultiByteToWideChar through syscall instead.
package enc

import (
	"errors"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	cpGBK  = 936   // GBK / GB2312 (ANSI code page on Chinese Windows)
	cpUTF8 = 65001 // UTF-8
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procMultiByteToWide = kernel32.NewProc("MultiByteToWideChar")
	procWideToMultiByte = kernel32.NewProc("WideCharToMultiByte")
)

// Available reports whether the GBK conversion APIs could be resolved.
func Available() bool {
	return procMultiByteToWide.Find() == nil && procWideToMultiByte.Find() == nil
}

// ToGBK converts UTF-8 text to GBK bytes. Characters that GBK cannot represent
// become '?' (the platform default), matching how cmd.exe and Excel behave.
func ToGBK(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	src := []byte(s)
	// UTF-8 -> UTF-16
	n, _, _ := procMultiByteToWide.Call(
		cpUTF8, 0,
		uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)),
		0, 0,
	)
	if n == 0 {
		return nil, errors.New("编码转换失败：无法把 UTF-8 输入解码为 UTF-16")
	}
	wide := make([]uint16, n)
	if r, _, _ := procMultiByteToWide.Call(
		cpUTF8, 0,
		uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)),
		uintptr(unsafe.Pointer(&wide[0])), uintptr(n),
	); r == 0 {
		return nil, errors.New("编码转换失败：UTF-8 解码")
	}

	// UTF-16 -> GBK
	need, _, _ := procWideToMultiByte.Call(
		cpGBK, 0,
		uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)),
		0, 0, 0, 0,
	)
	if need == 0 {
		return nil, errors.New("编码转换失败：当前系统不支持 GBK 代码页 936")
	}
	out := make([]byte, need)
	if r, _, _ := procWideToMultiByte.Call(
		cpGBK, 0,
		uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(need),
		0, 0,
	); r == 0 {
		return nil, errors.New("编码转换失败：无法转换为 GBK")
	}
	return out, nil
}

// FromGBK converts GBK bytes back to a UTF-8 string. It exists mainly so the
// round trip can be tested and so callers can verify an exported file.
func FromGBK(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	n, _, _ := procMultiByteToWide.Call(
		cpGBK, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0,
	)
	if n == 0 {
		return "", errors.New("解码失败：输入不是合法的 GBK 文本")
	}
	wide := make([]uint16, n)
	if r, _, _ := procMultiByteToWide.Call(
		cpGBK, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&wide[0])), uintptr(n),
	); r == 0 {
		return "", errors.New("解码失败：GBK -> UTF-16")
	}
	return string(utf16.Decode(wide)), nil
}
