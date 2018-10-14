package trace

import "github.com/loov/unpolluted/trace/dtrace"

func Supported() error { return dtrace.Supported() }
