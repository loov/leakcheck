package dtrace

import (
	"context"
	"errors"

	"github.com/loov/unpolluted/analyser"
)

func Supported() error {
	return errors.New("not supported")
}

func Program(ctx context.Context, analyser analyser.Analyser, cmd string, args ...string) (int, error) {
	return 1, errors.New("todo")
}
