package dmonitor

import "errors"

func Supported() error {
	return errors.New("not supported")
}
