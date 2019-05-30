package api

import (
	"strconv"
	"syscall"

	"github.com/loov/leakcheck/api/syscalls"
)

// Call defines a single syscall.
type Call interface {
	// Raw returns the fallback information that is available on all syscalls.
	Raw() Syscall
}

// Open is a syscall for opening a file, pipe or connection.
type Open struct {
	Syscall
	Path     string
	Flag     int // corresponding to os.OpenFile
	ResultFD int64
	Failed   bool
}

// Unlink is a syscall for unlinking (deleting) a file.
type Unlink struct {
	Syscall
	Path   string
	Failed bool
}

// Socket creates a new socket.
type Socket struct {
	Syscall
	ResultFD int64
	Failed   bool
}

// Bind binds a socket to an address.
type Bind struct {
	Syscall
	FD     int64
	Addr   string
	Failed bool
}

// Close closes a file, connection or socket.
type Close struct {
	Syscall
	FD     int64
	Failed bool
}

// Clone clones the process.
type Clone struct {
	Syscall
	Flag      int64 // corresponding to unix.CLONE_*
	ResultPID int64
	Failed    bool
}

// Kill is the syscall for killing another process.
type Kill struct {
	Syscall
	PID    int64
	Signal syscall.Signal
	Failed bool
}

// Syscall is the fallback when there isn't a specific struct
type Syscall struct {
	Number uint64
	Name   string
}

// Raw returns the information uninterpreted.
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

// Less implements sorting for syscalls.
func (call Syscall) Less(b Syscall) bool {
	// numeric order for numbers
	if call.Name == "" && b.Name == "" {
		return call.Number < b.Number
	}
	// alphabetical for names
	if call.Name != "" && b.Name != "" {
		return call.Name < b.Name
	}
	// sort numbered calls to the front
	return call.Name == ""
}
