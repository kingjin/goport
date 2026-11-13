package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// Console mode flags from wincon.h.
const enableVirtualTerminalProcessing = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enableVT turns on ANSI escape processing for stdout and stderr.
//
// Windows Terminal, and cmd.exe on recent Windows 10/11, render VT sequences
// once ENABLE_VIRTUAL_TERMINAL_PROCESSING is set on the console handle. Without
// it the user sees a literal "[1m" instead of bold text (or, worse, no colour at
// all). When the console does not support it the caller falls back to plain
// output.
func enableVT() bool {
	return enableVTHandle(stdOutputHandle) && enableVTHandle(stdErrorHandle)
}

// STD_OUTPUT_HANDLE = -11 and STD_ERROR_HANDLE = -12, passed as DWORD values.
const (
	stdOutputHandle = uintptr(uint32(0xFFFFFFF5))
	stdErrorHandle  = uintptr(uint32(0xFFFFFFF4))
)

func enableVTHandle(std uintptr) bool {
	h, _, _ := procGetStdHandle.Call(std)
	if h == 0 || h == ^uintptr(0) {
		return false
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false // redirected to a file/pipe, not a console
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	r, _, _ := procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

// ---- 桌面模式辅助 ------------------------------------------------------

var (
	shell32          = syscall.NewLazyDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
)

// openBrowserURL 用系统默认浏览器打开 url（ShellExecuteW，不弹命令行窗口）。
func openBrowserURL(url string) error {
	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	const swShownormal = 1
	r, _, callErr := procShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0, 0,
		swShownormal,
	)
	if r <= 32 {
		// ShellExecute 的返回值 <=32 都是错误码
		return fmt.Errorf("ShellExecute 返回 %d（%v）", r, callErr)
	}
	return nil
}

// waitForExit 在出错时停住窗口，避免双击启动的用户来不及看到原因就闪退。
func waitForExit(w io.Writer) {
	if !isTerminal(w) {
		return
	}
	fmt.Fprint(w, "\n按回车键退出…")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
