// Package npcap is a dependency-free, pure-Go binding to wpcap.dll (Npcap /
// WinPcap) on Windows.
//
// It talks to the DLL through syscall.LazyDLL instead of cgo, which keeps the
// scanner buildable with CGO_ENABLED=0: no gcc/clang and no C headers are
// required, and the result is a single self-contained executable.
//
// Only the parts of libpcap that a raw SYN scanner needs are bound: device
// enumeration, opening a live capture, BPF filters, packet injection, packet
// iteration and statistics.
package npcap

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Link-layer header types returned by pcap_datalink.
const (
	DLTNull   = 0  // BSD loopback encapsulation (Npcap loopback with DltNull=1)
	DLTEn10MB = 1  // Ethernet
	DLTRaw    = 12 // raw IP
)

// errbufSize mirrors PCAP_ERRBUF_SIZE in pcap.h.
const errbufSize = 256

// pcap_if flags.
const (
	PcapIfLoopback = 0x00000001
	PcapIfUp       = 0x00000002
	PcapIfRunning  = 0x00000004
)

var (
	loadOnce sync.Once
	loadErr  error

	dll *syscall.LazyDLL

	pFindAllDevs *syscall.LazyProc
	pFreeAllDevs *syscall.LazyProc
	pOpenLive    *syscall.LazyProc
	pClose       *syscall.LazyProc
	pCompile     *syscall.LazyProc
	pSetFilter   *syscall.LazyProc
	pFreeCode    *syscall.LazyProc
	pSendPacket  *syscall.LazyProc
	pNextEx      *syscall.LazyProc
	pGetErr      *syscall.LazyProc
	pDatalink    *syscall.LazyProc
	pLibVersion  *syscall.LazyProc
	pStats       *syscall.LazyProc
	pBreakLoop   *syscall.LazyProc

	// WinPcap/Npcap batch-injection extension (optional: absent on some builds).
	queueOnce sync.Once
	queueErr  error

	// pSetBuff is optional too (pcap_setbuff).
	pSetBuff *syscall.LazyProc

	pQueueAlloc    *syscall.LazyProc
	pQueueQueue    *syscall.LazyProc
	pQueueTransmit *syscall.LazyProc
	pQueueDestroy  *syscall.LazyProc
)

// Load resolves wpcap.dll and its entry points. It is safe to call from
// multiple goroutines and returns a descriptive error when Npcap is missing.
func Load() error {
	loadOnce.Do(func() {
		dll = syscall.NewLazyDLL("wpcap.dll")
		if err := dll.Load(); err != nil {
			loadErr = fmt.Errorf("无法加载 wpcap.dll：%w（请先安装 Npcap，下载地址 https://npcap.com/#download）", err)
			return
		}
		procs := []struct {
			dst  **syscall.LazyProc
			name string
		}{
			{&pFindAllDevs, "pcap_findalldevs"},
			{&pFreeAllDevs, "pcap_freealldevs"},
			{&pOpenLive, "pcap_open_live"},
			{&pClose, "pcap_close"},
			{&pCompile, "pcap_compile"},
			{&pSetFilter, "pcap_setfilter"},
			{&pFreeCode, "pcap_freecode"},
			{&pSendPacket, "pcap_sendpacket"},
			{&pNextEx, "pcap_next_ex"},
			{&pGetErr, "pcap_geterr"},
			{&pDatalink, "pcap_datalink"},
			{&pLibVersion, "pcap_lib_version"},
			{&pStats, "pcap_stats"},
			{&pBreakLoop, "pcap_breakloop"},
		}
		for _, p := range procs {
			proc := dll.NewProc(p.name)
			if err := proc.Find(); err != nil {
				loadErr = fmt.Errorf("wpcap.dll 缺少导出函数 %s：%w", p.name, err)
				return
			}
			*p.dst = proc
		}
	})
	return loadErr
}

// Version reports the Npcap/libpcap version string.
func Version() string {
	if err := Load(); err != nil {
		return "unavailable: " + err.Error()
	}
	r, _, _ := pLibVersion.Call()
	if r == 0 {
		return "unknown"
	}
	return goString(ptrFromUint(r))
}

// Addr is one address entry of a capture device.
type Addr struct {
	IP      net.IP
	Netmask net.IP
	Broad   net.IP
}

// Device is a capture-capable interface as reported by Npcap itself.
type Device struct {
	Name        string // e.g. \Device\NPF_{GUID}
	Description string
	Flags       uint32
	Addrs       []Addr
}

// IsLoopback reports whether the device is a loopback pseudo-interface.
func (d Device) IsLoopback() bool { return d.Flags&PcapIfLoopback != 0 }

// FindAllDevs asks Npcap for its own device list.
//
// Note: Npcap installs with "restrict to administrators" enabled by default, in
// which case PacketGetAdapterNames inside pcap_findalldevs fails with access
// denied. The scanner therefore derives device names from iphlpapi (see package
// netinfo) and uses this call only as an elevated diagnostic.
func FindAllDevs() ([]Device, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var errbuf [errbufSize]byte
	var head unsafe.Pointer
	ret, _, _ := pFindAllDevs.Call(uintptr(unsafe.Pointer(&head)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(ret) != 0 {
		msg := ansiToString(&errbuf[0])
		if strings.Contains(msg, "(5)") || strings.Contains(msg, "(20)") {
			msg += "（拒绝访问：需要管理员权限）"
		}
		return nil, errors.New("pcap_findalldevs 失败：" + msg)
	}
	if head == nil {
		return nil, errors.New("pcap_findalldevs 未返回任何网卡")
	}
	defer func() { pFreeAllDevs.Call(uintptr(head)) }()

	ps := unsafe.Sizeof(uintptr(0))
	// struct pcap_if   { next; name; description; addresses; flags }
	// struct pcap_addr { next; addr; netmask; broadaddr; dstaddr }
	offNext, offName, offDesc, offAddrs := uintptr(0), ps, 2*ps, 3*ps
	offFlags := 4 * ps

	var out []Device
	for cur := head; cur != nil; {
		dev := Device{
			Name:        goString(*(*unsafe.Pointer)(unsafe.Add(cur, offName))),
			Description: goString(*(*unsafe.Pointer)(unsafe.Add(cur, offDesc))),
			Flags:       *(*uint32)(unsafe.Add(cur, offFlags)),
		}
		for a := *(*unsafe.Pointer)(unsafe.Add(cur, offAddrs)); a != nil; {
			addr := Addr{
				IP:      sockaddrIP(*(*unsafe.Pointer)(unsafe.Add(a, ps))),
				Netmask: sockaddrIP(*(*unsafe.Pointer)(unsafe.Add(a, 2*ps))),
				Broad:   sockaddrIP(*(*unsafe.Pointer)(unsafe.Add(a, 3*ps))),
			}
			if addr.IP != nil {
				dev.Addrs = append(dev.Addrs, addr)
			}
			a = *(*unsafe.Pointer)(unsafe.Add(a, 0))
		}
		out = append(out, dev)
		cur = *(*unsafe.Pointer)(unsafe.Add(cur, offNext))
	}
	return out, nil
}

// Handle wraps a pcap_t*.
type Handle struct {
	p  uintptr
	mu sync.Mutex // serialises Close
}

// ErrClosed is returned once a handle has been closed.
var ErrClosed = errors.New("pcap 句柄已关闭")

// OpenLive opens a capture handle on the named device.
//
// snaplen is the snapshot length (65536 captures whole frames), toMs is the
// read timeout consumed by NextPacket, and promisc enables promiscuous mode.
// Opening a device requires administrator rights under Npcap's default policy.
func OpenLive(name string, snaplen, toMs int, promisc bool) (*Handle, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	if snaplen <= 0 {
		snaplen = 65536
	}
	if toMs <= 0 {
		toMs = 50
	}
	var errbuf [errbufSize]byte
	cname, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("网卡名称无效 %q：%w", name, err)
	}
	var promiscFlag uintptr
	if promisc {
		promiscFlag = 1
	}
	r, _, _ := pOpenLive.Call(
		uintptr(unsafe.Pointer(cname)),
		uintptr(snaplen),
		promiscFlag,
		uintptr(toMs),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if r == 0 {
		return nil, openError(ansiToString(&errbuf[0]))
	}
	return &Handle{p: r}, nil
}

// openError turns libpcap's error buffer into one clear, actionable message.
//
// Npcap reports the same generic "Error opening adapter" for a wrong device name
// and for its kernel-mode access check; only the process token tells them apart,
// and on a non-elevated process the raw system text ("系统找不到指定的设备") is
// noise, so it is replaced by the actual cause.
func openError(raw string) error {
	base, code := splitErrCode(raw)
	text := sysErrText(code)

	if code == 5 || code == 20 || strings.Contains(base, "Error opening adapter") {
		if !IsElevated() {
			return errors.New("无法打开 Npcap 驱动：当前进程不是管理员权限。" +
				"\n  Npcap 驱动默认只允许管理员访问。请任选其一：" +
				"\n    1) 用「以管理员身份运行」的 PowerShell / CMD 重新执行；" +
				"\n    2) 加 -m connect 用普通 socket 扫描（无需管理员，速率较低）。")
		}
		if text != "" {
			return fmt.Errorf("无法打开 Npcap 驱动：%s（系统错误 %d：%s）", base, code, text)
		}
		return fmt.Errorf("无法打开 Npcap 驱动：%s", base)
	}
	if code == 1068 || strings.Contains(base, "not been started") {
		return errors.New("Npcap 服务未运行，请执行：sc start npcap")
	}
	if text != "" && base != "" && !strings.Contains(base, text) {
		return fmt.Errorf("%s（系统错误 %d：%s）", base, code, text)
	}
	if base != "" {
		return errors.New(base)
	}
	if text != "" {
		return fmt.Errorf("系统错误 %d：%s", code, text)
	}
	return errors.New("未知错误")
}

// goString converts a NUL-terminated C string pointer to a Go string.
func goString(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	n := 0
	for n < 4096 {
		if *(*byte)(unsafe.Add(p, uintptr(n))) == 0 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(p), n))
}

// ptrFromUint reinterprets a pointer-valued uintptr returned by a DLL call as an
// unsafe.Pointer. The value is written into a pointer-typed slot so that the
// conversion is explicit rather than an arithmetic uintptr conversion.
func ptrFromUint(v uintptr) unsafe.Pointer {
	var p unsafe.Pointer
	*(*uintptr)(unsafe.Pointer(&p)) = v
	return p
}
