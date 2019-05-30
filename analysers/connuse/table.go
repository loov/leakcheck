package connuse

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/loov/leakcheck/api"
)

const (
	fileLimit = 100000
)

type Table struct {
	Verbose bool
	Open    []Socket
}

type Socket struct {
	ID     int64
	Addr   string
	Status Status
	Logged bool
}

type Status int

const (
	StatusUninitialized = Status(0)
	StatusOpen          = Status(1)
	StatusClosed        = Status(2)
)

func New(verbose bool) *Table {
	return &Table{Verbose: verbose}
}

func (table *Table) opened(fd int64) {
	if fd < 0 {
		// TODO: should this be reported?
		return
	}
	if fd > fileLimit {
		// TODO: should this be logged?
		return
	}

	if table.Verbose {
		fmt.Fprintf(os.Stderr, "> socket open (%v)\n", fd)
	}

	if fd >= int64(len(table.Open)) {
		table.Open = append(table.Open, make([]Socket, int(fd)-len(table.Open)+1)...)
	}

	desc := &table.Open[fd]
	desc.ID = fd
	desc.Status = StatusOpen
}

func (table *Table) bind(fd int64, addr string) {
	if fd < 0 {
		// TODO: should this be reported?
		return
	}
	if fd > fileLimit || fd > int64(len(table.Open)) {
		// TODO: should this be logged?
		return
	}

	if table.Verbose {
		fmt.Fprintf(os.Stderr, "> socket bind %q (%v)\n", addr, fd)
	}
	desc := &table.Open[fd]
	desc.Addr = addr
}

func (table *Table) closed(fd int64) {
	if fd < 0 {
		// TODO: should this be reported?
		return
	}
	if fd >= int64(len(table.Open)) {
		// TODO: should this be reported?
		return
	}

	desc := &table.Open[fd]
	if table.Verbose {
		fmt.Fprintf(os.Stderr, "> close %q (%v)\n", desc.Addr, fd)
	}

	if desc.Status == StatusOpen {
		desc.Status = StatusClosed
	}
}

func (table *Table) Handle(call api.Call) {
	switch call := call.(type) {
	case api.Socket:
		if !call.Failed {
			table.opened(call.ResultFD)
		}
	case api.Bind:
		if !call.Failed {
			table.bind(call.FD, call.Addr)
		}
	case api.Close:
		if !call.Failed {
			table.closed(call.FD)
		}
	}
}

func (table *Table) Err() error {
	var buf strings.Builder

	for fd := range table.Open {
		desc := &table.Open[fd]
		if desc.Status == StatusOpen {
			fmt.Fprintf(&buf, "unclosed socket %q (%d)\n", desc.Addr, desc.ID)
		}
	}

	if buf.Len() == 0 {
		return nil
	}
	return errors.New(buf.String())
}

func (table *Table) WriteResult(w io.Writer) (int64, error) {
	return 0, nil
}
