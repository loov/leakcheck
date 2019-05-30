package api

import (
	"errors"
	"io"
	"strings"
)

// Analyser defines how different calls can be analyzed.
type Analyser interface {
	// Handle handles the call, which might
	//  print output immediately or
	//  collect information and write the information later.
	Handle(call Call)
	// Err returns whether some error happened during collection.
	Err() error
	// WriteResult writes analyser result to w.
	WriteResult(w io.Writer) (int64, error)
}

// Analysers combines multiple analysers into a single implementation.
type Analysers []Analyser

// Add adds multiple analysers to the collection.
func (xs *Analysers) Add(x ...Analyser) {
	*xs = append(*xs, x...)
}

// Handle handles call with all analysers sequentially.
func (xs Analysers) Handle(call Call) {
	for _, x := range xs {
		x.Handle(call)
	}
}

// Err returns whether any error happened during collection.
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

// WriteResult writes all the outputs from analysers.
func (xs Analysers) WriteResult(w io.Writer) (int64, error) {
	var errs []string
	var total int64
	for _, x := range xs {
		n, err := x.WriteResult(w)
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
