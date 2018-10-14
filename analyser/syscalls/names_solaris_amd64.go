package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[int64]string{
	syscall.SYS_EXECVE: "execve",
	syscall.SYS_FCNTL:  "fcntl",
}
