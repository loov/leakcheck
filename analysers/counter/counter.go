package counter

import (
	"fmt"
	"io"
	"sort"

	"github.com/loov/leakcheck/api"
)

type Counter struct {
	Calls map[api.Syscall]uint64
}

func New() *Counter {
	return &Counter{
		Calls: make(map[api.Syscall]uint64, 1000),
	}
}

func (counter *Counter) Handle(call api.Call) {
	counter.Calls[call.Raw()]++
}

func (counter *Counter) Err() error { return nil }

func (counter *Counter) WriteResult(w io.Writer) (int64, error) {
	calls := []api.Syscall{}
	for call := range counter.Calls {
		calls = append(calls, call)
	}
	sort.Slice(calls, func(i, k int) bool { return calls[i].Less(calls[k]) })

	var total int64
	for _, call := range calls {
		count := counter.Calls[call]
		n, err := fmt.Fprintf(w, "%-14s %d\n", call.String(), count)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
