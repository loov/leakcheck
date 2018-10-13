package main

import (
	"io"
	"syscall"
)

type Analyser interface {
	Handle(pid int, registers syscall.PtraceRegs)
	Err() error
	WriteTo(w io.Writer) (int64, error)
}

type Analysers []Analyser

func (xs Analysers) Handle(pid int, registers syscall.PtraceRegs) {
	for _, x := range xs {
		x.Handle(pid, registers)
	}
}

func (xs Analysers) Err() error {
	var errs []error
	for _, x := range xs {
		errs = append(errs, x.Err())
	}
	return CombineErrors(errs...)
}

func (xs Analysers) WriteTo(w io.Writer) (int64, error) {
	var errs []error
	var total int64
	for _, x := range xs {
		n, err := x.WriteTo(w)
		total += n
		errs = append(errs, err)
	}
	return total, CombineErrors(errs...)
}
