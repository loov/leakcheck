package nttrace

import (
	"context"
	"errors"
	"os/exec"

	"github.com/loov/unpolluted/analyser"
)

func Supported() error {
	var err error

	_, err = exec.LookPath("NtTrace.exe")
	if err == nil {
		return nil
	}

	_, err = exec.LookPath("stracent.exe")
	if err == nil {
		return nil
	}

	return errors.New("requires NtTrace.exe or straceNt.exe")
}

func Program(ctx context.Context, analyser analyser.Analyser, cmd string, args ...string) (int, error) {
	return 1, errors.New("todo")
}
