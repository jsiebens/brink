package util

import (
	"io"
	"os"
)

type stdinOut struct {
}

func (s stdinOut) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (s stdinOut) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

func (s stdinOut) Close() error {
	return nil
}

func PipeStdInOut(from io.ReadWriteCloser) {
	Pipe(from, &stdinOut{})
}

func Pipe(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	pipe := func(closer chan bool, dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		closer <- true
	}

	c := make(chan bool, 2)
	go pipe(c, from, to)
	go pipe(c, to, from)
	<-c
}
