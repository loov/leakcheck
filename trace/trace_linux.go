package trace

import "github.com/loov/unpolluted/trace/ptrace"

func Supported() error { return ptrace.Supported() }
