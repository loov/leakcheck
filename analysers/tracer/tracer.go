package tracer

import (
	"fmt"
	"io"
	"os"

	"github.com/loov/leakcheck/api"
)

// Tracer implements an analyzer that prints everything to stderr.
type Tracer struct{}

// New creates a new Tracer.
func New() *Tracer {
	return &Tracer{}
}

// Handler prints the api.Call to stderr.
func (counter *Tracer) Handle(call api.Call) {
	fmt.Fprintln(os.Stderr, call)
}

// Err returns nothing.
func (counter *Tracer) Err() error { return nil }

// WriteResult writes nothing as a result.
func (counter *Tracer) WriteResult(w io.Writer) (int64, error) { return 0, nil }
