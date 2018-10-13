package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

import "C"

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

	counter := NewCounter()

	code, err := monitor(counter, *trace, args[0], args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	if *summary {
		counter.WriteTo(os.Stderr)
	}

	if err := FileDescriptors.Verify(counter); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

func monitor(counter *Counter, trace bool, command string, args ...string) (int, error) {
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
			if id != syscall.SYS_FUTEX && id != syscall.SYS_RT_SIGACTION {
				fmt.Fprintf(os.Stderr, "> %s\n", SyscallName(id))
				switch id {
				case syscall.SYS_CLOSE:
					fmt.Fprintf(os.Stderr, ". close: %v\n", registers.Rdi)
				case syscall.SYS_OPEN:
					fmt.Fprintf(os.Stderr, ". open: %v got %v\n", stringArgument(pid, registers.Rdi), int64(registers.Rax))
				case syscall.SYS_OPENAT:
					fmt.Fprintf(os.Stderr, ". openat: %q got %v\n", stringArgument(pid, registers.Rsi), int64(registers.Rax))
				case syscall.SYS_WRITE:
					fmt.Fprintf(os.Stderr, ". write: %v got %v\n", registers.Rdi, int64(registers.Rax))
				}
			}
		}

		counter.Called(id)

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

func stringArgument(pid int, addr uint64) string {
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
