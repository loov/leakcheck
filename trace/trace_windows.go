package trace

import (
	"context"

	"github.com/loov/unpolluted/api"
	"github.com/loov/unpolluted/trace/nttrace"
)

func Supported() error { return nttrace.Supported() }

func Program(ctx context.Context, analyser api.Analyser, cmd string, args ...string) (int, error) {
	return nttrace.Program(ctx, analyser, cmd, args)
}
