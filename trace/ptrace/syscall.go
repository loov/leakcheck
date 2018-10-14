package ptrace

import (
	"bytes"
	"syscall"
)

func SyscallStringArgument(pid int, addr uint64) string {
	var buffer [4096]byte
	n, err := syscall.PtracePeekData(pid, uintptr(addr), buffer[:])
	if err != nil {
		return ""
	}

	k := bytes.IndexByte(buffer[:n], 0)
	if k <= n {
		n = k
	}
	return string(buffer[:n])
}
