package main

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Tracker struct {
	Calls   []uint64
	Unknown uint64
}

func NewTracker() *Tracker {
	return &Tracker{
		Calls:   make([]uint64, SyscallCount()),
		Unknown: 0,
	}
}

func (tracker *Tracker) Called(id uint64) {
	if id >= uint64(len(tracker.Calls)) {
		atomic.AddUint64(&tracker.Unknown, 1)
		return
	}
	atomic.AddUint64(&tracker.Calls[id], 1)
}

func (tracker *Tracker) WriteTo(w io.Writer) (int64, error) {
	total := int64(0)
	for id, count := range tracker.Calls {
		if count == 0 {
			continue
		}
		n, err := fmt.Fprintf(w, "%-14s %d\n", SyscallName(uint64(id)), count)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	if tracker.Unknown > 0 {
		n, err := fmt.Fprintf(w, "unknown %d\n", tracker.Unknown)
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

func (pair *Pair) Verify(tracker *Tracker) error {
	opened := uint64(0)
	closed := uint64(0)
	for _, call := range pair.Opening {
		opened += tracker.Calls[call]
	}
	for _, call := range pair.Closing {
		closed += tracker.Calls[call]
	}
	if opened != closed {
		return fmt.Errorf("%s unbalanced opening %d closing %d", pair.Name, opened, closed)
	}
	return nil
}
