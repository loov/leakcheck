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
		Calls:   make([]int, SyscallCount()),
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

func (tracker *Tracker) WriteTo(w io.Writer) error {
	for id, count := range tracker.Calls {
		if count == 0 {
			continue
		}
		_, err := fmt.Fprintf(w, "%s %d\n", SyscallName(id), count)
		if err != nil {
			return err
		}
	}
	if tracker.Unknown > 0 {
		_, err := fmt.Fprintf(w, "unknown %d\n", tracker.Unknown)
		if err != nil {
			return err
		}
	}

	return nil
}
