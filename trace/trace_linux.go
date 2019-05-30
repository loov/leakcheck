package trace

import (
	"context"

	"github.com/loov/leakcheck/api"
	"github.com/loov/leakcheck/trace/ptrace"
)

// Supported returns whether tracing is supported.
func Supported() error { return ptrace.Supported() }

// Program starts cmd with args and attaches tracer and analyser.
func Program(ctx context.Context, analyser api.Analyser, cmd string, args ...string) (int, error) {
	return ptrace.Program(ctx, analyser, cmd, args...)
}
