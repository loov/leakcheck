package dtrace

import (
	"bufio"
	"fmt"
	"io"

	"github.com/loov/leakcheck/api"
)

type Parser struct {
	source  io.Reader
	scanner *bufio.Scanner
}

func NewParser(source io.Reader) *Parser {
	return &Parser{
		source:  source,
		scanner: bufio.NewScanner(source),
	}
}

/*
access("/AppleInternal/XBS/.isChrooted\0", 0x0, 0x0)		 = -1 Err#2
bsdthread_register(0x7FFF60BA9418, 0x7FFF60BA9408, 0x2000)		 = 1073742047 0
sysctlbyname(kern.bootargs, 0xD, 0x7FFEEFBFE230, 0x7FFEEFBFE228, 0x0)		 = 0 0
issetugid(0x0, 0x0, 0x0)		 = 0 0
ioctl(0x2, 0x4004667A, 0x7FFEEFBFDA44)		 = 0 0
*/

func (parser *Parser) Next() (api.Call, error) {
	for parser.scanner.Scan() {
		line := parser.scanner.Text()
		call := parseCall(line)
		fmt.Printf("%#+v\n", call)
		return call, nil
	}

	if err := parser.scanner.Err(); err != nil {
		return nil, err
	}

	return nil, io.EOF
}

func parseCall(s string) api.Call {
	fmt.Println(s)
	p := 0
	for p < len(s) && isIdent(s[p]) {
		p++
	}
	if p >= len(s) || s[p] != '(' {
		return nil
	}
	name := s[:p]

	return api.Syscall{
		Name: name,
	}
}

func isIdent(c byte) bool {
	return 'a' <= c && c <= 'z' ||
		'A' <= c && c <= 'Z' ||
		'0' <= c && c <= '9' ||
		c == '_'
}

func parseArgument(s string) (string, int) {
	for p := range s {

	}
}
