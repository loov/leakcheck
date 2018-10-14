package trace

import (
	"context"

	"github.com/loov/unpolluted/analyser"
	"github.com/loov/unpolluted/trace/nttrace"
)

func Supported() error { return nttrace.Supported() }

func Program(ctx context.Context, analyser analyser.Analyser, cmd string, args ...string) error {
	return nttrace.Program(ctx, analyser, cmd, args)
}
