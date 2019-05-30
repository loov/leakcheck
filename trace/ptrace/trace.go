package ptrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/loov/leakcheck/api"
	"golang.org/x/sys/unix"
)

// Supported returns whether tracing is supported.
func Supported() error {
	return nil
}

// Program starts cmd with args and attaches tracer and analyser.
func Program(ctx context.Context, analyser api.Analyser, command string, args ...string) (int, error) {
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

	var status unix.WaitStatus
	pid := cmd.Process.Pid
	for {
		var err error
		var registers unix.PtraceRegs
		err = unix.PtraceGetRegs(pid, &registers)
		if err != nil {
			return 1, fmt.Errorf("ptrace get regs failed: %v", err)
		}

		call := registersToCall(pid, registers)
		analyser.Handle(call)

		err = unix.PtraceSyscall(pid, 0)
		if err != nil {
			return 1, fmt.Errorf("ptrace syscall failed: %v", err)
		}

		_, err = unix.Wait4(pid, &status, 0, nil)
		if err != nil {
			return 1, fmt.Errorf("ptrace wait4 failed: %v", err)
		}

		if status.Exited() {
			break
		}
	}

	return status.ExitStatus(), nil
}
