package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/loov/leakcheck/analysers/connuse"
	"github.com/loov/leakcheck/analysers/counter"
	"github.com/loov/leakcheck/analysers/fileuse"
	"github.com/loov/leakcheck/analysers/procuse"
	"github.com/loov/leakcheck/analysers/tempuse"
	"github.com/loov/leakcheck/analysers/tracer"
	"github.com/loov/leakcheck/api"
	"github.com/loov/leakcheck/trace"
)

func main() {
	verbose := flag.Bool("verbose", false, "enable verbose output")
	summary := flag.Bool("summary", false, "summary of analysers")

	fileuseEnabled := flag.Bool("file", true, "monitor file usage")
	connuseEnabled := flag.Bool("conn", true, "monitor connection usage")
	procuseEnabled := flag.Bool("proc", false, "monitor process usage (flaky)")
	counterEnabled := flag.Bool("count", false, "count syscalls")
	tempuseEnabled := flag.Bool("temp", false, "monitor proper temporary usage")
	tracerEnabled := flag.Bool("trace", false, "trace all monitored syscalls")

	flag.Parse()

	if *verbose {
		*summary = true
	}

	var analysers api.Analysers
	if *fileuseEnabled {
		analysers.Add(fileuse.New(*verbose))
	}
	if *connuseEnabled {
		analysers.Add(connuse.New(*verbose))
	}
	if *procuseEnabled {
		analysers.Add(procuse.New(*verbose))
	}
	if *tempuseEnabled {
		analysers.Add(tempuse.New(*verbose))
	}
	if *counterEnabled {
		analysers.Add(counter.New())
	}
	if *tracerEnabled {
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
