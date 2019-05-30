package trace

import (
	"context"

	"github.com/loov/leakcheck/api"
	"github.com/loov/leakcheck/trace/dtrace"
)

// Supported returns whether tracing is supported.
func Supported() error { return dtrace.Supported() }

// Program starts cmd with args and attaches tracer and analyser.
func Program(ctx context.Context, analyser api.Analyser, cmd string, args ...string) (int, error) {
	return dtrace.Program(ctx, analyser, cmd, args...)
}
