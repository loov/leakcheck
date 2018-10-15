package ptrace

import (
	"github.com/loov/leakcheck/api"
	"golang.org/x/sys/unix"
)

func registersToCall(pid int, registers unix.PtraceRegs) api.Call {
	raw := api.Syscall{
		Number: uint64(registers.Orig_eax),
	}

	switch raw.Number {
	case unix.SYS_OPEN:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Ebx)),
			Flag:     int(registers.Ecx),
			ResultFD: int64(registers.Eax),
			Failed:   registers.Eax < 0,
		}
	case unix.SYS_OPENAT:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Ecx)),
			Flag:     int(registers.Edx),
			ResultFD: int64(registers.Eax),
			Failed:   registers.Eax < 0,
		}

	case unix.SYS_CLOSE:
		return api.Close{
			Syscall: raw,
			FD:      int64(registers.Ebx),
			Failed:  registers.Eax != 0,
		}

	case unix.SYS_UNLINK:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Ebx)),
			Failed:  registers.Eax != 0,
		}
	case unix.SYS_UNLINKAT:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Ecx)),
			Failed:  registers.Eax != 0,
		}

	case unix.SYS_SOCKETCALL:
		// TODO: find correct table for socket call constants
		socketcall := int(registers.Ebx)
		switch socketcall {
		// case unix.SYS_SOCKET:
		case 1:
			raw.Number = unix.SYS_SOCKET
			return api.Socket{
				Syscall:  raw,
				ResultFD: int64(registers.Eax),
				Failed:   registers.Eax < 0,
			}
		// case unix.SYS_BIND:
		case 2:
			raw.Number = unix.SYS_BIND
			return api.Bind{
				Syscall: raw,
				FD:      int64(registers.Ebx),
				// TODO: detect addr
				Failed: registers.Eax != 0,
			}
		}
	}

	return raw
}
