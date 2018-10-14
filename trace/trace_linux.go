package trace

import (
	"context"

	"github.com/loov/unpolluted/api"
	"github.com/loov/unpolluted/trace/ptrace"
)

func Supported() error { return ptrace.Supported() }

func Program(ctx context.Context, analyser api.Analyser, cmd string, args ...string) (int, error) {
	return ptrace.Program(ctx, analyser, cmd, args)
}
