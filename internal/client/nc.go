package client

import (
	"context"
	"net"
	"os"
)

func StartNC(ctx context.Context, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	closer := make(chan struct{}, 2)
	go pipe(closer, conn, os.Stdin)
	go pipe(closer, os.Stdout, conn)
	<-closer

	return nil
}
