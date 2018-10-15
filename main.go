// +build !linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/loov/leakcheck/analysers/counter"
	"github.com/loov/leakcheck/api"
	"github.com/loov/leakcheck/trace"
)

func main() {
	count := flag.Bool("count", false, "count syscalls")
	verbose := flag.Bool("trace", false, "enable tracing")
	summary := flag.Bool("summary", false, "summary of analysers")
	flag.Parse()

	if *verbose {
		*summary = true
	}

	var analysers api.Analysers
	analysers = append(analysers,
		counter.New(*verbose),
	)

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "leakcheck PROGRAM [args]\n")
		os.Exit(1)
	}

	code, err := trace.Process(context.Background(), analysers, args[0], args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}

	if *summary {
		analysers.WriteTo(os.Stderr)
	}

	if err := analysers.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}
