package main

import (
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"testing"
)

// Tests need to be run with:
//
//   go test -exec ./leakcheck .

func TestFileLeak(t *testing.T) {
	file, err := ioutil.TempFile("", "leak-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = file
}

func TestDeleteOpenFile(t *testing.T) {
	file, err := ioutil.TempFile("", "leak-*.txt")
	if err != nil {
		t.Fatal(err)
	}

	_ = os.Remove(file.Name())
	_ = file.Close()
}

func TestOpenFile(t *testing.T) {
	{
		// opening/reading allowed
		file, err := os.Open("main.go")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	{
		file, err := os.Create("testfile~")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		os.Remove("testfile~")
	}
}

func TestServerLeak(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln
}

func TestConnLeak(t *testing.T) {
	conn, err := net.Dial("tcp", "loov.io:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn
}

func TestExecNormal(t *testing.T) {
	cmd := exec.Command("sleep", "0")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestExecLeak(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestExecKill(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
}
