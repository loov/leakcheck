package procuse

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/loov/leakcheck/api"
	"golang.org/x/sys/unix"
)

type Table struct {
	Verbose bool
	Open    map[int64]*Process
}

type Process struct {
	PID    int64
	Name   string
	Status Status
	Logged bool
}

type Status int

const (
	StatusUninitialized = Status(0)
	StatusRunning       = Status(1)
	StatusExited        = Status(2)
	StatusKilled        = Status(3)
)

func New(verbose bool) *Table {
	return &Table{
		Verbose: verbose,
		Open:    map[int64]*Process{},
	}
}

func (table *Table) opened(pid int64) {
	process := &Process{
		PID:    pid,
		Status: StatusRunning,
	}
	table.Open[pid] = process
}

func (table *Table) shutdown(pid int64) {
	process, ok := table.Open[pid]
	if !ok {
		return
	}

	delete(table.Open, pid)
	process.Status = StatusKilled
}

func (table *Table) Handle(call api.Call) {
	switch call := call.(type) {
	case api.Clone:
		childFlag := int64(unix.SIGCHLD)
		if !call.Failed && call.Flag&childFlag == childFlag {
			table.opened(call.ResultPID)
		}
	case api.Kill:
		if call.Signal == unix.SIGKILL || call.Signal == unix.SIGQUIT || call.Signal == unix.SIGSTOP {
			table.shutdown(call.PID)
		}
	}
}

func (table *Table) Err() error {
	var buf strings.Builder

	for _, proc := range table.Open {
		fmt.Fprintf(&buf, "unclosed process %d\n", proc.PID)
	}

	if buf.Len() == 0 {
		return nil
	}
	return errors.New(buf.String())
}

func (table *Table) WriteTo(w io.Writer) (int64, error) {
	return 0, nil
}
