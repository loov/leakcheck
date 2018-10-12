package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	tracker := NewTracker()
	defer tracker.WriteTo(os.Stderr)

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr, cmd.Stdin, cmd.Stdout = os.Stderr, os.Stdin, os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:  true,
		Setpgid: true,
	}

	// start process
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start command failed: %v\n", err)
		os.Exit(1)
	}

	// wait program to stop
	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "wait command failed: %v\n", err)
		os.Exit(1)
	}

	var registers syscall.PtraceRegs
	var status syscall.WaitStatus
	pid := cmd.Process.Pid
	for !status.Exited() {
		err = syscall.PtraceGetRegs(pid, &registers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptrace get regs failed: %v\n", err)
			os.Exit(1)
		}

		tracker.Called(registers.Orig_rax)

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptrace syscall failed: %v\n", err)
			os.Exit(1)
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptrace wait4 failed: %v\n", err)
			os.Exit(1)
		}
	}
}
