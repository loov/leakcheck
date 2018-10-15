package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/loov/leakcheck/analysers/connuse"
	"github.com/loov/leakcheck/analysers/counter"
	"github.com/loov/leakcheck/analysers/fileuse"
	"github.com/loov/leakcheck/analysers/tracer"
	"github.com/loov/leakcheck/api"
	"github.com/loov/leakcheck/trace"
)

func main() {
	count := flag.Bool("count", false, "count syscalls")
	dotrace := flag.Bool("trace", false, "trace all monitored syscalls")
	verbose := flag.Bool("verbose", false, "enable verbose output")
	summary := flag.Bool("summary", false, "summary of analysers")
	flag.Parse()

	if *verbose {
		*summary = true
	}

	var analysers api.Analysers
	analysers.Add(fileuse.New(*verbose))
	analysers.Add(connuse.New(*verbose))

	if *count {
		analysers.Add(counter.New())
	}

	if *dotrace {
		analysers.Add(tracer.New())
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "leakcheck PROGRAM [args]\n")
		os.Exit(1)
	}

	code, err := trace.Program(context.Background(), analysers, args[0], args[1:]...)
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
