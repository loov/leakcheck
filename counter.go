package main

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Counter struct {
	Calls   []uint64
	Unknown uint64
}

func NewCounter() *Counter {
	return &Counter{
		Calls:   make([]uint64, SyscallCount()),
		Unknown: 0,
	}
}

func (counter *Counter) Called(id uint64) {
	if id >= uint64(len(counter.Calls)) {
		atomic.AddUint64(&counter.Unknown, 1)
		return
	}
	atomic.AddUint64(&counter.Calls[id], 1)
}

func (counter *Counter) WriteTo(w io.Writer) (int64, error) {
	total := int64(0)
	for id, count := range counter.Calls {
		if count == 0 {
			continue
		}
		n, err := fmt.Fprintf(w, "%-14s %d\n", SyscallName(uint64(id)), count)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	if counter.Unknown > 0 {
		n, err := fmt.Fprintf(w, "unknown %d\n", counter.Unknown)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

type Pair struct {
	Name    string
	Opening []uint64
	Closing []uint64
}

func (pair *Pair) Verify(counter *Counter) error {
	opened := uint64(0)
	closed := uint64(0)
	for _, call := range pair.Opening {
		opened += counter.Calls[call]
	}
	for _, call := range pair.Closing {
		closed += counter.Calls[call]
	}
	if opened != closed {
		return fmt.Errorf("%s unbalanced opening %d closing %d", pair.Name, opened, closed)
	}
	return nil
}
