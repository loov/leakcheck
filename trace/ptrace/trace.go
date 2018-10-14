package ptrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/loov/unpolluted/analyser"
	"github.com/loov/unpolluted/api"
)

func Supported() error {
	return nil
}

func Program(ctx context.Context, analyser analyser.Analyser, command string, args ...string) (int, error) {
	cmd := exec.Command(command, args...)
	cmd.Stderr, cmd.Stdin, cmd.Stdout = os.Stderr, os.Stdin, os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	// TODO: propagate signals

	// TODO: handle ctx.Cancel

	// start process
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start command failed: %v", err)
	}

	// TODO: handle ctx.Cancel
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// wait program to hit a trap
	_ = cmd.Wait()

	var status syscall.WaitStatus
	pid := cmd.Process.Pid
	for {
		var err error
		var registers syscall.PtraceRegs
		err = syscall.PtraceGetRegs(pid, &registers)
		if err != nil {
			return 1, fmt.Errorf("ptrace get regs failed: %v", err)
		}

		call := registersToCall(pid, registers)
		analyser.Handle(call)

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return 1, fmt.Errorf("ptrace syscall failed: %v", err)
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			return 1, fmt.Errorf("ptrace wait4 failed: %v", err)
		}

		if status.Exited() {
			break
		}
	}

	return status.ExitStatus(), nil
}

func registersToCall(pid int, registers syscall.PtraceRegs) api.Call {
	raw := api.Syscall{
		Number: registers.Orig_rax,
	}

	switch raw.Number {
	case syscall.SYS_OPEN:
		return api.Open{
			Syscall:  raw,
			Path:     SyscallStringArgument(pid, registers.Rdi),
			ResultFD: int64(registers.Rax),
			Failed:   int64(registers.Rax) < 0,
		}
	case syscall.SYS_OPENAT:
		return api.Open{
			Syscall:  raw,
			Path:     SyscallStringArgument(pid, registers.Rdi),
			ResultFD: int64(registers.Rax),
			Failed:   int64(registers.Rax) < 0,
		}
	case syscall.SYS_CLOSE:
		return api.Close{
			Syscall: raw,
			FD:      int64(registers.Rdi),
			Failed:  int64(registers.Rdi) < 0,
		}
	}

	return raw
}
