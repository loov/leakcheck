package main

import (
	"io/ioutil"
	"testing"
)

// Tests need to be run with:
//
//   go test -exec ./unpolluted .

func TestFileLeak(t *testing.T) {
	file, err := ioutil.TempFile("", "leak-*.txt")
	_, _ = file, err
}
