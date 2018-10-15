package api

import (
	"strconv"

	"github.com/loov/leakcheck/api/syscalls"
)

type Call interface {
	Raw() Syscall
}

type Open struct {
	Syscall
	Path     string
	Flag     int // corresponding to os.OpenFile
	ResultFD int64
	Failed   bool
}

type Unlink struct {
	Syscall
	Path   string
	Failed bool
}

type Close struct {
	Syscall
	FD     int64
	Failed bool
}

// Syscall is the fallback when there isn't a specific struct
type Syscall struct {
	Number uint64
	Name   string
}

func (call Syscall) Raw() Syscall { return call }

func (call Syscall) String() string {
	if call.Name != "" {
		return call.Name
	}

	name, ok := syscalls.Name[call.Number]
	if !ok {
		return "Syscall(" + strconv.Itoa(int(call.Number)) + ")"
	}
	return name
}

func (a Syscall) Less(b Syscall) bool {
	// numeric order for numbers
	if a.Name == "" && b.Name == "" {
		return a.Number < b.Number
	}
	// alphabetical for names
	if a.Name != "" && b.Name != "" {
		return a.Name < b.Name
	}
	// sort numbered calls to the front
	return a.Name == ""
}
