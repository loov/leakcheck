package dtrace

import (
	"context"
	"errors"
	"os/exec"

	"github.com/loov/unpolluted/analyser"
)

func Supported() error {
	_, err := exec.LookPath("dtruss")
	if err == nil {
		return nil
	}

	return errors.New("requires dtruss")
}

func Program(ctx context.Context, analyser analyser.Analyser, cmd string, args ...string) (int, error) {
	return 1, errors.New("todo")
}
