package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{
	syscall.SYS_EXECVE: "execve",
	syscall.SYS_FCNTL:  "fcntl",
}
