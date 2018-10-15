package ptrace

import (
	"github.com/loov/leakcheck/api"
	"golang.org/x/sys/unix"
)

func registersToCall(pid int, registers unix.PtraceRegs) api.Call {
	raw := api.Syscall{
		Number: uint64(registers.Orig_rax),
	}

	switch raw.Number {
	case unix.SYS_OPEN:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Rdi)),
			Flag:     int(registers.Rsi),
			ResultFD: int64(registers.Rax),
			Failed:   int64(registers.Rax) < 0,
		}
	case unix.SYS_OPENAT:
		return api.Open{
			Syscall:  raw,
			Path:     stringArgument(pid, uintptr(registers.Rsi)),
			Flag:     int(registers.Rdx),
			ResultFD: int64(registers.Rax),
			Failed:   int64(registers.Rax) < 0,
		}

	case unix.SYS_CLOSE:
		return api.Close{
			Syscall: raw,
			FD:      int64(registers.Rdi),
			Failed:  registers.Rax != 0,
		}

	case unix.SYS_UNLINK:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Rdi)),
			Failed:  registers.Rax != 0,
		}
	case unix.SYS_UNLINKAT:
		return api.Unlink{
			Syscall: raw,
			Path:    stringArgument(pid, uintptr(registers.Rsi)),
			Failed:  registers.Rax != 0,
		}

	case unix.SYS_SOCKET:
		return api.Socket{
			Syscall:  raw,
			ResultFD: int64(registers.Rax),
			Failed:   int64(registers.Rax) < 0,
		}
	case unix.SYS_BIND:
		addr := bindAddrArgument(pid, uintptr(registers.Rsi))
		return api.Bind{
			Syscall: raw,
			FD:      int64(registers.Rdi),
			Addr:    addr,
			Failed:  registers.Rax != 0,
		}
	}

	return raw
}
