package api

import (
	"strconv"

	"github.com/loov/unpolluted/api/syscalls"
)

type Call interface {
	Raw() Syscall
}

type Open struct {
	Syscall
	Path     string
	ResultFD int64
	Failed   bool
}

type Close struct {
	Syscall
	FD     int64
	Failed bool
}

// Syscall is the fallback when there isn't a specific struct
type Syscall struct {
	Number int64
	Name   string
}

func (call Syscall) Raw() Syscall { return call }

func (call Syscall) String() string {
	if call.Name != "" {
		return call.Name
	}

	name, ok := syscalls.Name[int64(call.Number)]
	if !ok {
		return "Syscall(" + strconv.Itoa(int(call.Number)) + ")"
	}
	return name
}
