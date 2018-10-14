// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	matches, err := filepath.Glob(filepath.Join(runtime.GOROOT(), "src", "syscall", "zsysnum_*.go"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find zsysnum_*: %v\n", err)
		os.Exit(1)
	}

	for _, match := range matches {
		generate(match)
	}
}

func generate(sourceFile string) {
	fmt.Fprintf(os.Stdout, "generating names for %q\n", sourceFile)
	fset := token.NewFileSet()

	srcdata, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open %q: %v\n", sourceFile, err)
		return
	}

	file, err := parser.ParseFile(fset, sourceFile, string(srcdata), parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse %q: %v\n", sourceFile, err)
		return
	}

	output := &bytes.Buffer{}

	fmt.Fprintln(output, `package syscalls`)
	fmt.Fprintln(output)
	fmt.Fprintln(output, `import "syscall"`)
	fmt.Fprintln(output)
	fmt.Fprintln(output, `var _ = syscall.Exit`)
	fmt.Fprintln(output)
	fmt.Fprintln(output, `var Name = map[int64]string{`)

	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if len(x.Names) != 1 {
				panic("unhandled")
			}
			fmt.Fprintf(output, "\tsyscall.%v: %q,\n", x.Names[0].Name, cleanupSysname(x.Names[0].Name))
			return false
		}
		return true
	})

	fmt.Fprintln(output, `}`)

	formatted, err := format.Source(output.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to format result: %v\n", err)
		return
	}

	platform := strings.TrimPrefix(filepath.Base(sourceFile), "zsysnum_")
	tableFile := "names_" + platform
	err = ioutil.WriteFile(tableFile, formatted, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write %q: %v\n", tableFile, err)
		return
	}
}

func cleanupSysname(s string) string {
	return strings.ToLower(strings.TrimPrefix(s, "SYS_"))
}
