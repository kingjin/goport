package npcap

import (
	"syscall"
	"unsafe"
)

var (
	procRegGetValue = advapi32.NewProc("RegGetValueW")
)

// DriverAdminOnly reports the Npcap install policy
// HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly, which
// defaults to 1 ("restrict the driver to administrators").
//
// This matters for startup time: when the policy is on and the process is not
// elevated, pcap_open_live eventually fails, but Npcap takes seconds to decide.
// Reading the policy first lets the caller skip that attempt entirely and fall
// back to connect() immediately.
func DriverAdminOnly() bool {
	const (
		hkeyLocalMachine = 0x80000002
		rrfRtRegDword    = 0x00000010
	)
	subkey, err := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\npcap\Parameters`)
	if err != nil {
		return false
	}
	name, err := syscall.UTF16PtrFromString("AdminOnly")
	if err != nil {
		return false
	}
	var value uint32
	size := uint32(unsafe.Sizeof(value))
	r, _, _ := procRegGetValue.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(subkey)),
		uintptr(unsafe.Pointer(name)),
		rrfRtRegDword,
		0,
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Pointer(&size)),
	)
	if int32(r) != 0 {
		return false // key missing or unreadable: assume the permissive default
	}
	return value != 0
}

// CanInject reports whether this process may open the Npcap driver right now.
// When it returns false, a SYN scan cannot work and the caller should use the
// connect() fallback without paying for a slow failed open.
func CanInject() bool {
	if IsElevated() {
		return true
	}
	return !DriverAdminOnly()
}
