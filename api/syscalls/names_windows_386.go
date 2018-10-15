package syscalls

import "syscall"

var _ = syscall.Exit

var Name = map[uint64]string{}
