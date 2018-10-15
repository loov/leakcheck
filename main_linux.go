package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

import "C"

func main() {
	count := flag.Bool("count", false, "count syscalls")
	trace := flag.Bool("trace", false, "enable tracing")
	summary := flag.Bool("summary", false, "summary of analysers")
	flag.Parse()

	if *trace {
		*summary = true
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "leakcheck PROGRAM [args]\n")
		os.Exit(1)
	}

	var analysers Analysers

	if *count {
		analysers = append(analysers, NewCounter(*trace))
	}

	analysers = append(analysers, NewFileDescriptorAnalyser(*trace))

	code, err := monitor(analysers, args[0], args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}

	if *summary {
		analysers.WriteTo(os.Stderr)
	}

	if err := analysers.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

func monitor(analyser Analyser, command string, args ...string) (int, error) {
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

		analyser.Handle(pid, registers)

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
