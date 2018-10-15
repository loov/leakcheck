package tracer

import (
	"fmt"
	"io"
	"os"

	"github.com/loov/leakcheck/api"
)

type Tracer struct{}

func New() *Tracer {
	return &Tracer{}
}

func (counter *Tracer) Handle(call api.Call) {
	fmt.Fprintln(os.Stderr, call)
}

func (counter *Tracer) Err() error { return nil }

func (counter *Tracer) WriteTo(w io.Writer) (int64, error) { return 0, nil }
