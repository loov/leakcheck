package api

import (
	"errors"
	"io"
	"strings"
)

type Analyser interface {
	Handle(call Call)
	Err() error
	WriteTo(w io.Writer) (int64, error)
}

type Analysers []Analyser

func (xs *Analysers) Add(x ...Analyser) {
	*xs = append(*xs, x...)
}

func (xs Analysers) Handle(call Call) {
	for _, x := range xs {
		x.Handle(call)
	}
}

func (xs Analysers) Err() error {
	var errs []string
	for _, x := range xs {
		err := x.Err()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "\n"))
}

func (xs Analysers) WriteTo(w io.Writer) (int64, error) {
	var errs []string
	var total int64
	for _, x := range xs {
		n, err := x.WriteTo(w)
		total += n
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		return total, nil
	}
	return total, errors.New(strings.Join(errs, "\n"))
}
