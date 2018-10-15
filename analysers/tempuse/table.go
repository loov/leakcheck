package tempuse

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/loov/leakcheck/api"
)

const (
	fileLimit = 100000
)

type Table struct {
	Verbose bool
	Temp    string

	OutsideTemp []string
}

func New(verbose bool) *Table {
	return &Table{
		Verbose: verbose,
		Temp:    os.TempDir(),
	}
}

func (table *Table) Handle(call api.Call) {
	switch call := call.(type) {
	case api.Open:
		if !call.Failed {
			create := call.Flag & (os.O_CREATE | os.O_APPEND | os.O_RDWR)
			if create != 0 {
				// TODO: better temp check
				if !strings.HasPrefix(call.Path, table.Temp) {
					table.OutsideTemp = append(table.OutsideTemp, call.Path)
				}
			}
		}
	}
}

func (table *Table) Err() error {
	var buf strings.Builder

	for _, file := range table.OutsideTemp {
		fmt.Fprintf(&buf, "created non-temp %q\n", file)
	}

	if buf.Len() == 0 {
		return nil
	}
	return errors.New(buf.String())
}

func (table *Table) WriteTo(w io.Writer) (int64, error) {
	return 0, nil
}
