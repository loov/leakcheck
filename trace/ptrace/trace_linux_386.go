package ptrace

import (
	"syscall"

	"github.com/loov/leakcheck/api"
)

func registersToCall(pid int, registers syscall.PtraceRegs) api.Call {
	raw := api.Syscall{
		Number: registers.Orig_rax,
	}

	switch raw.Number {
	case syscall.SYS_OPEN:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Ebp)),
			Flag:     int(registers.Ecx),
			ResultFD: int64(registers.Rax),
			Failed:   registers.Rax < 0,
		}
	case syscall.SYS_OPENAT:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Ecx)),
			Flag:     int(registers.Rdx),
			ResultFD: int64(registers.Rax),
			Failed:   registers.Rax < 0,
		}

	case syscall.SYS_CLOSE:
		return api.Close{
			Syscall: raw,
			FD:      int64(registers.Ebp),
			Failed:  registers.Rax != 0,
		}

	case syscall.SYS_UNLINK:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Ebp)),
			Failed:  registers.Rax != 0,
		}
	case syscall.SYS_UNLINKAT:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Ecx)),
			Failed:  registers.Rax != 0,
		}

	case syscall.SYS_SOCKET:
		return api.Socket{
			Syscall:  raw,
			ResultFD: int64(registers.Rax),
			Failed:   registers.Rax < 0,
		}
	case syscall.SYS_BIND:
		return api.Bind{
			Syscall: raw,
			FD:      int64(registers.Orig_rax),
			Failed:  registers.Rax != 0,
		}
	}

	return raw
}
