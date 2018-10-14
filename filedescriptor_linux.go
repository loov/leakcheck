package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

const (
	fileDescriptorRecordLimit = 100000
)

type FileDescriptorAnalyser struct {
	Trace bool
	Open  []FileDescriptor
}

type FileDescriptor struct {
	Fd     int64
	Name   string
	Status FileDescriptorStatus
}

type FileDescriptorStatus int

const (
	StatusUninitialized = FileDescriptorStatus(0)
	StatusOpen          = FileDescriptorStatus(1)
	StatusClosed        = FileDescriptorStatus(2)
	StatusErrored       = FileDescriptorStatus(3)
)

func NewFileDescriptorAnalyser(trace bool) *FileDescriptorAnalyser {
	return &FileDescriptorAnalyser{Trace: trace}
}

func (analyser *FileDescriptorAnalyser) opened(name string, fd int64) {
	if fd < 0 {
		// TODO: should this be reported?
		return
	}
	if fd > fileDescriptorRecordLimit {
		// TODO: should this be logged?
		return
	}

	if analyser.Trace {
		fmt.Fprintf(os.Stderr, "> open %q (%v)\n", name, fd)
	}

	if fd >= int64(len(analyser.Open)) {
		analyser.Open = append(analyser.Open, make([]FileDescriptor, int(fd)-len(analyser.Open)+1)...)
	}

	desc := &analyser.Open[fd]
	desc.Fd = fd
	desc.Name = name
	desc.Status = StatusOpen
}

func (analyser *FileDescriptorAnalyser) closed(fd int64) {
	if fd < 0 {
		// TODO: should this be reported?
		return
	}
	if fd >= int64(len(analyser.Open)) {
		// TODO: should this be reported?
		return
	}

	desc := &analyser.Open[fd]
	if analyser.Trace {
		fmt.Fprintf(os.Stderr, "> close %q (%v)\n", desc.Name, fd)
	}

	if desc.Status == StatusOpen {
		desc.Status = StatusClosed
	}
}

func (analyser *FileDescriptorAnalyser) Handle(pid int, registers syscall.PtraceRegs) {
	syscallID := registers.Orig_rax

	switch syscallID {
	case syscall.SYS_OPEN:
		name := SyscallStringArgument(pid, registers.Rdi)
		fd := int64(registers.Rax)
		if fd >= 0 {
			analyser.opened(name, fd)
		}
	case syscall.SYS_OPENAT:
		name := SyscallStringArgument(pid, registers.Rsi)
		fd := int64(registers.Rax)
		if fd >= 0 {
			analyser.opened(name, fd)
		}
	case syscall.SYS_CLOSE:
		fd := int64(registers.Rdi)
		analyser.closed(fd)
	}
}

func (analyser *FileDescriptorAnalyser) Err() error {
	var buf strings.Builder

	for fd := range analyser.Open {
		desc := &analyser.Open[fd]
		if desc.Status == StatusOpen {
			fmt.Fprintf(&buf, "unclosed file %q (%d)\n", desc.Name, desc.Fd)
		}
	}

	if buf.Len() == 0 {
		return nil
	}
	return errors.New(buf.String())
}

func (analyser *FileDescriptorAnalyser) WriteTo(w io.Writer) (int64, error) {
	return 0, nil
}
