package main

import (
	"io/ioutil"
)

func main() {
	file, err := ioutil.TempFile("", "leak-*.txt")
	_, _ = file, err
}
