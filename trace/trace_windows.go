package trace

import "github.com/loov/unpolluted/trace/nttrace"

func Supported() error { return nttrace.Supported() }
