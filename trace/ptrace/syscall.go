package ptrace

import (
	"bytes"
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

func stringArgument(pid int, addr uintptr) string {
	var buffer [4096]byte
	n, err := unix.PtracePeekData(pid, addr, buffer[:])
	if err != nil {
		return ""
	}

	k := bytes.IndexByte(buffer[:n], 0)
	if k <= n {
		n = k
	}
	return string(buffer[:n])
}

func bindAddrArgument(pid int, addr uintptr) string {
	var buffer [4096]byte
	_, err := unix.PtracePeekData(pid, addr, buffer[:])
	if err != nil {
		return ""
	}

	family := *(*uint16)(unsafe.Pointer(&buffer[0]))
	switch family {
	// TODO: other calls
	case unix.AF_INET:
		pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(&buffer[0]))
		sa := new(unix.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr

		return net.JoinHostPort(net.IP(sa.Addr[:]).String(), strconv.Itoa(sa.Port))

	case unix.AF_INET6:
		pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(&buffer[0]))
		sa := new(unix.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return net.JoinHostPort(net.IP(sa.Addr[:]).String(), strconv.Itoa(sa.Port))
	}

	return ""
}
