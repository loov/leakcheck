package analyser

import (
	"strconv"

	"github.com/loov/unpolluted/analyser/syscalls"
)

type Call interface{}

type Open struct {
	Path             string
	ResultDescriptor int64
}

type Close struct {
	Descriptor int64
}

// SyscallNumber is the fallback when there isn't a specific struct
type SyscallNumber int64

func (num SyscallNumber) Name() string {
	name, ok := syscalls.Name[int64(num)]
	if !ok {
		return "SyscallNumber(" + strconv.Itoa(int(num)) + ")"
	}
	return name
}

// SyscallName is the fallback when there isn't a specific struct
type SyscallName string
