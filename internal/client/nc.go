package client

import (
	"context"
	"fmt"
	"net"
	"os"
)

func StartNC(ctx context.Context, addr, host, port string) error {
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

func PrintListenerInfo(ctx context.Context, addr, host, port string) error {
	fmt.Printf("\n  Listening on %s\n\n", addr)
	return nil
}
