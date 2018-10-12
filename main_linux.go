package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	trace := flag.Bool("trace", false, "trace all syscalls")
	summary := flag.Bool("summary", false, "summary of syscalls")
	flag.Parse()

	if *trace {
		*summary = true
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "unpolluted PROGRAM [args]\n")
		os.Exit(1)
	}

	tracker := NewTracker()

	code, err := monitor(tracker, *trace, args[0], args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	if *summary {
		tracker.WriteTo(os.Stderr)
	}

	if err := FileDescriptors.Verify(tracker); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

func monitor(tracker *Tracker, trace bool, command string, args ...string) (int, error) {
	cmd := exec.Command(command, args...)
	cmd.Stderr, cmd.Stdin, cmd.Stdout = os.Stderr, os.Stdin, os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	// start process
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start command failed: %v", err)
	}

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

		id := registers.Orig_rax
		if trace {
			fmt.Fprintf(os.Stderr, "> %s\n", SyscallName(id))
		}
		tracker.Called(id)

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return 1, fmt.Errorf("ptrace syscall failed: %v", err)
			os.Exit(1)
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
