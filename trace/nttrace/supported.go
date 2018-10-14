package nttrace

import (
	"errors"
	"os/exec"
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
