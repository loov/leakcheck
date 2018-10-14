package dtrace

import "errors"

func Supported() error {
	return errors.New("not supported")
}
