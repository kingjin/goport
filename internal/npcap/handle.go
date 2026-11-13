package npcap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// SetFilter installs a BPF filter expression on the capture handle.
func (h *Handle) SetFilter(expr string) error {
	if h == nil || h.p == 0 {
		return ErrClosed
	}
	cexpr, err := syscall.BytePtrFromString(expr)
	if err != nil {
		return fmt.Errorf("过滤器表达式无效：%w", err)
	}
	// struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }
	var prog struct {
		length uint32
		insns  unsafe.Pointer
	}
	ret, _, _ := pCompile.Call(
		h.p,
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Pointer(cexpr)),
		1,          // optimize
		0xffffffff, // PCAP_NETMASK_UNKNOWN
	)
	if int32(ret) != 0 {
		return fmt.Errorf("编译 BPF 过滤器 %q 失败：%s", expr, h.GetErr())
	}
	defer func() { pFreeCode.Call(uintptr(unsafe.Pointer(&prog))) }()
	ret, _, _ = pSetFilter.Call(h.p, uintptr(unsafe.Pointer(&prog)))
	if int32(ret) != 0 {
		return fmt.Errorf("安装 BPF 过滤器 %q 失败：%s", expr, h.GetErr())
	}
	return nil
}

// SendPacket injects a single link-layer frame.
func (h *Handle) SendPacket(frame []byte) error {
	if h == nil || h.p == 0 {
		return ErrClosed
	}
	if len(frame) == 0 {
		return errors.New("空报文")
	}
	ret, _, _ := pSendPacket.Call(h.p, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if int32(ret) != 0 {
		return fmt.Errorf("发送失败：%s", h.GetErr())
	}
	return nil
}

// NextPacket returns the next captured frame.
//
// The returned slice aliases libpcap's internal buffer and is valid only until
// the following call to NextPacket: callers must parse it immediately or copy
// it. A nil slice with a nil error means the read timed out.
func (h *Handle) NextPacket() ([]byte, error) {
	if h == nil || h.p == 0 {
		return nil, ErrClosed
	}
	var hdr, data unsafe.Pointer
	ret, _, _ := pNextEx.Call(h.p, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	switch int32(ret) {
	case 1:
		if data == nil || hdr == nil {
			return nil, nil
		}
		// struct pcap_pkthdr { struct timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
		// On Windows a timeval is two 32-bit longs, so caplen lives at offset 12.
		caplen := *(*uint32)(unsafe.Add(hdr, 12))
		if caplen == 0 {
			return nil, nil
		}
		return unsafe.Slice((*byte)(data), caplen), nil
	case 0:
		return nil, nil // read timeout
	case -2:
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("pcap_next_ex 失败：%s", h.GetErr())
	}
}

// BreakLoop asks a blocking NextPacket call to return.
func (h *Handle) BreakLoop() {
	if h == nil || h.p == 0 {
		return
	}
	pBreakLoop.Call(h.p)
}

// DataLink reports the link-layer header type of the handle.
func (h *Handle) DataLink() int {
	if h == nil || h.p == 0 {
		return -1
	}
	r, _, _ := pDatalink.Call(h.p)
	return int(int32(r))
}

// GetErr returns libpcap's last error string for this handle.
func (h *Handle) GetErr() string {
	if h == nil || h.p == 0 {
		return "handle closed"
	}
	r, _, _ := pGetErr.Call(h.p)
	if r == 0 {
		return "unknown error"
	}
	return goString(ptrFromUint(r))
}

// Stats reports capture counters: received, dropped by the kernel and dropped
// by the adapter.
func (h *Handle) Stats() (recv, drop, ifdrop uint32) {
	if h == nil || h.p == 0 {
		return 0, 0, 0
	}
	var st struct{ recv, drop, ifdrop uint32 }
	if r, _, _ := pStats.Call(h.p, uintptr(unsafe.Pointer(&st))); int32(r) != 0 {
		return 0, 0, 0
	}
	return st.recv, st.drop, st.ifdrop
}

// SetBuffer asks the driver for a larger capture ring buffer (pcap_setbuff, an
// Npcap/WinPcap extension). A bigger buffer is what keeps a fast scan from
// dropping replies when they arrive in a burst.
func (h *Handle) SetBuffer(bytes int) error {
	if h == nil || h.p == 0 {
		return ErrClosed
	}
	if err := Load(); err != nil {
		return err
	}
	if pSetBuff == nil {
		proc := dll.NewProc("pcap_setbuff")
		if err := proc.Find(); err != nil {
			return fmt.Errorf("wpcap.dll 不支持 pcap_setbuff：%w", err)
		}
		pSetBuff = proc
	}
	if bytes < 64<<10 {
		bytes = 64 << 10
	}
	if r, _, _ := pSetBuff.Call(h.p, uintptr(bytes)); int32(r) != 0 {
		return fmt.Errorf("pcap_setbuff(%d) 失败：%s", bytes, h.GetErr())
	}
	return nil
}

// Close releases the handle. It is safe to call more than once.
func (h *Handle) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.p == 0 {
		return
	}
	pBreakLoop.Call(h.p)
	pClose.Call(h.p)
	h.p = 0
}

// ---- batched injection ------------------------------------------------

// sendQueue mirrors C's pcap_send_queue:
//
//	u_int maxlen; u_int len; u_char *buffer;
type sendQueue struct {
	maxlen uint32
	length uint32
	buffer unsafe.Pointer
}

// BatchQueue is a fixed-size frame queue bound to one capture handle.
//
// pcap_sendqueue_transmit injects a whole batch with one driver call, which is
// roughly an order of magnitude faster than one pcap_sendpacket per frame.
type BatchQueue struct {
	h   *Handle
	q   *sendQueue
	max int
	// maxFrames caps one burst: a burst that is too large provokes an equally
	// large reply burst that the capture buffer cannot always absorb.
	maxFrames int
	// Usable reports whether the batch API is available and initialised.
	Usable bool
}

// QueueSupported reports whether wpcap.dll exports the send-queue API.
func QueueSupported() bool {
	queueOnce.Do(func() {
		if err := Load(); err != nil {
			queueErr = err
			return
		}
		procs := []struct {
			dst  **syscall.LazyProc
			name string
		}{
			{&pQueueAlloc, "pcap_sendqueue_alloc"},
			{&pQueueQueue, "pcap_sendqueue_queue"},
			{&pQueueTransmit, "pcap_sendqueue_transmit"},
			{&pQueueDestroy, "pcap_sendqueue_destroy"},
		}
		for _, p := range procs {
			proc := dll.NewProc(p.name)
			if err := proc.Find(); err != nil {
				queueErr = fmt.Errorf("wpcap.dll 不支持批量发送（缺少 %s）：%w", p.name, err)
				return
			}
			*p.dst = proc
		}
	})
	return queueErr == nil
}

// NewBatchQueue allocates a batch queue of maxBytes for handle h.
func NewBatchQueue(h *Handle, maxBytes int) *BatchQueue {
	bq := &BatchQueue{h: h, max: maxBytes}
	if h == nil || h.p == 0 || !QueueSupported() {
		return bq
	}
	if maxBytes <= 0 || maxBytes > 16<<20 {
		maxBytes = 1 << 20
	}
	bq.maxFrames = 128
	r, _, _ := pQueueAlloc.Call(uintptr(maxBytes))
	if r == 0 {
		return bq
	}
	bq.q = (*sendQueue)(ptrFromUint(r))
	bq.Usable = true
	return bq
}

// Add appends one frame. It returns false when the queue is full (or the burst
// limit is reached) and the caller must Transmit first.
func (q *BatchQueue) Add(frame []byte) bool {
	if !q.Usable || q.q == nil || len(frame) == 0 {
		return false
	}
	if q.maxFrames > 0 && q.q.length >= uint32(q.maxFrames) {
		return false
	}
	// struct pcap_pkthdr { struct timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
	var hdr struct {
		sec    int32
		usec   int32
		caplen uint32
		length uint32
	}
	hdr.caplen = uint32(len(frame))
	hdr.length = uint32(len(frame))
	r, _, _ := pQueueQueue.Call(
		uintptr(unsafe.Pointer(q.q)),
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&frame[0])),
	)
	return r == 0
}

// Len is the number of frames currently queued.
func (q *BatchQueue) Len() int {
	if !q.Usable || q.q == nil {
		return 0
	}
	return int(q.q.length)
}

// Transmit injects everything queued and returns the byte count accepted by the
// driver. The queue is reset afterwards so it can be reused immediately.
func (q *BatchQueue) Transmit() (int, error) {
	if !q.Usable || q.q == nil || q.q.length == 0 {
		return 0, nil
	}
	if q.h == nil || q.h.p == 0 {
		return 0, ErrClosed
	}
	// Pass pcap_t* (h.p), never the Go *Handle wrapper. The third argument
	// (sync=1) waits until the frames are on the wire; with sync=0 Npcap may
	// keep referencing the buffer and reusing it corrupts the batch.
	r, _, _ := pQueueTransmit.Call(q.h.p, uintptr(unsafe.Pointer(q.q)), 1)
	sent := int(r)
	q.q.length = 0
	if sent == 0 {
		return 0, fmt.Errorf("批量发送失败：%s", q.h.GetErr())
	}
	return sent, nil
}

// Free releases the queue buffer.
func (q *BatchQueue) Free() {
	if q == nil || q.q == nil {
		return
	}
	pQueueDestroy.Call(uintptr(unsafe.Pointer(q.q)))
	q.q = nil
	q.Usable = false
}

// ---- error text and token helpers -------------------------------------

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procMultiByteToWide = kernel32.NewProc("MultiByteToWideChar")
	procGetCurrentProc  = kernel32.NewProc("GetCurrentProcess")
	procFormatMessage   = kernel32.NewProc("FormatMessageW")
	procLocalFree       = kernel32.NewProc("LocalFree")
	procOpenProcessTok  = advapi32.NewProc("OpenProcessToken")
	procGetTokenInfo    = advapi32.NewProc("GetTokenInformation")
)

// ansiToString converts an ANSI (system code page) C string to UTF-8 so that
// libpcap's error messages stay readable on non-English Windows.
func ansiToString(p *byte) string {
	if p == nil {
		return ""
	}
	n := 0
	for {
		c := *(*byte)(unsafe.Add(unsafe.Pointer(p), uintptr(n)))
		if c == 0 || n > 1024 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	const cpACP = 0
	const flags = 0
	wide, _, _ := procMultiByteToWide.Call(
		cpACP, flags,
		uintptr(unsafe.Pointer(p)), uintptr(n),
		0, 0,
	)
	if wide == 0 {
		return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
	}
	buf := make([]uint16, wide)
	if r, _, _ := procMultiByteToWide.Call(
		cpACP, flags,
		uintptr(unsafe.Pointer(p)), uintptr(n),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(wide),
	); r == 0 {
		return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
	}
	return strings.TrimSpace(string(utf16.Decode(buf)))
}

// IsElevated reports whether the current process holds an elevated token, which
// is what Npcap's default driver policy requires.
func IsElevated() bool {
	cur, _, _ := procGetCurrentProc.Call()
	var token syscall.Handle
	const tokenQuery = 0x0008
	if r, _, _ := procOpenProcessTok.Call(cur, tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)
	var isElevated uint32
	var retLen uint32
	const tokenElevation = 20 // TokenElevation
	if r, _, _ := procGetTokenInfo.Call(
		uintptr(token), tokenElevation,
		uintptr(unsafe.Pointer(&isElevated)), unsafe.Sizeof(isElevated),
		uintptr(unsafe.Pointer(&retLen)),
	); r == 0 {
		return false
	}
	return isElevated != 0
}

// splitErrCode separates libpcap's "text  (code)" error buffer into its parts.
func splitErrCode(msg string) (string, uint32) {
	i := strings.LastIndex(msg, "(")
	j := strings.LastIndex(msg, ")")
	if i < 0 || j <= i+1 {
		return strings.TrimSpace(msg), 0
	}
	code, err := strconv.Atoi(strings.TrimSpace(msg[i+1 : j]))
	if err != nil {
		return strings.TrimSpace(msg), 0
	}
	return strings.TrimSpace(msg[:i]), uint32(code)
}

// sysErrText formats a Win32 error code with FormatMessageW, which returns
// UTF-16 and therefore renders correctly in any console code page.
func sysErrText(code uint32) string {
	if code == 0 {
		return ""
	}
	const (
		formatMessageAllocateBuffer = 0x00000100
		formatMessageIgnoreInserts  = 0x00000200
		formatMessageFromSystem     = 0x00001000
	)
	var buf unsafe.Pointer
	r, _, _ := procFormatMessage.Call(
		formatMessageFromSystem|formatMessageIgnoreInserts|formatMessageAllocateBuffer,
		0, uintptr(code), 0,
		uintptr(unsafe.Pointer(&buf)), 0, 0,
	)
	if r == 0 || buf == nil {
		return ""
	}
	defer procLocalFree.Call(uintptr(buf))
	n := 0
	for n < 4096 {
		if *(*uint16)(unsafe.Add(buf, uintptr(n)*2)) == 0 {
			break
		}
		n++
	}
	b := make([]uint16, n)
	for i := 0; i < n; i++ {
		b[i] = *(*uint16)(unsafe.Add(buf, uintptr(i)*2))
	}
	return strings.TrimSpace(string(utf16.Decode(b)))
}

// sockaddrIP decodes a Windows sockaddr* into an IP address.
func sockaddrIP(p unsafe.Pointer) net.IP {
	if p == nil {
		return nil
	}
	switch family := *(*uint16)(p); family {
	case syscall.AF_INET:
		// struct sockaddr_in: family(2) port(2) addr(4) zero(8)
		b := unsafe.Slice((*byte)(unsafe.Add(p, 4)), 4)
		return net.IPv4(b[0], b[1], b[2], b[3]).To4()
	case syscall.AF_INET6:
		// struct sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4)
		b := unsafe.Slice((*byte)(unsafe.Add(p, 8)), 16)
		ip := make(net.IP, 16)
		copy(ip, b)
		return ip
	}
	return nil
}
