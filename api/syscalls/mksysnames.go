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
	glob := filepath.Join(runtime.GOROOT(), "src", "cmd", "vendor", "golang.org", "x", "sys", "unix", "zsysnum_*.go")
	matches, err := filepath.Glob(glob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find zsysnum_*: %v\n", err)
		os.Exit(1)
	}

	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "failed to find zsysnum_*\n")
		os.Exit(1)
	}
	for _, match := range matches {
		generate(match)
	}
}

func generate(sourceFile string) {
	platform := strings.TrimPrefix(filepath.Base(sourceFile), "zsysnum_")

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
	fmt.Fprintln(output, `import "golang.org/x/sys/unix"`)
	fmt.Fprintln(output)
	fmt.Fprintln(output, `var _ = unix.Exit`)
	fmt.Fprintln(output)
	fmt.Fprintln(output, `var Name = map[uint64]string{`)

	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if len(x.Names) != 1 {
				panic("unhandled")
			}

			name := x.Names[0].Name
			if platform == "linux_386.go" && name == "MADVISE1" {
				return false
			}

			if x.Comment == nil {
				fmt.Fprintf(output, "\tunix.%v: %q,\n", name, cleanupSysname(name))
			} else {
				fmt.Fprintf(output, "\tunix.%v: %q, // %v\n", name, cleanupSysname(name), strings.TrimSpace(x.Comment.Text()))
			}
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
