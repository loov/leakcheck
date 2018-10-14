package main

import (
	"fmt"
	"io"
	"syscall"
)

type Counter struct {
	Trace   bool
	Calls   []uint64
	Unknown uint64
}

func NewCounter(trace bool) *Counter {
	return &Counter{
		Trace:   trace,
		Calls:   make([]uint64, SyscallCount()),
		Unknown: 0,
	}
}

func (counter *Counter) Handle(pid int, registers syscall.PtraceRegs) {
	syscallID := registers.Orig_rax
	if syscallID >= uint64(len(counter.Calls)) {
		counter.Unknown++
		return
	}
	counter.Calls[syscallID]++
}

func (counter *Counter) Err() error { return nil }

func (counter *Counter) WriteTo(w io.Writer) (int64, error) {
	total := int64(0)
	for syscallID, count := range counter.Calls {
		if count == 0 {
			continue
		}
		n, err := fmt.Fprintf(w, "%-14s %d\n", SyscallName(uint64(syscallID)), count)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	if counter.Unknown > 0 {
		n, err := fmt.Fprintf(w, "unknown %d\n", counter.Unknown)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	return total, nil
}
