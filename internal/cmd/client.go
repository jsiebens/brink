package cmd

import (
	"context"
	"fmt"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	exec "golang.org/x/sys/execabs"
	"io/ioutil"
	"net"
	"os"
)

func connectCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "connect",
		SilenceUsage: true,
	}

	var proxyAddrFlag string
	var targetAddrFlag string
	var listenPort uint64
	var listenOnStdin bool
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "")
	command.Flags().Uint64Var(&listenPort, "listen-port", 0, "")
	command.Flags().BoolVar(&listenOnStdin, "listen-on-stdin", false, "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(ProxiroProxy, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		targetAddr := getString(ProxiroTarget, targetAddrFlag)
		if targetAddr == "" {
			return fmt.Errorf("required flag --target-addr is missing")
		}

		_, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return err
		}

		if !listenOnStdin {
			return client.StartClient(cmd.Context(), proxyAddr, listenPort, targetAddr, caFile, tlsSkipVerify, func(ctx context.Context, addr string) error {
				fmt.Printf("\n  Listening on %s\n\n", addr)
				return nil
			})
		} else {
			return client.StartClient(cmd.Context(), proxyAddr, 0, targetAddr, caFile, tlsSkipVerify, client.StartNC)
		}
	}

	return command
}

func sshCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "ssh",
		SilenceUsage: true,
	}

	var proxyAddrFlag string
	var targetAddrFlag string
	var userName string
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "")
	command.Flags().StringVarP(&userName, "username", "u", "", "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		cancelCtx, cancelFunc := context.WithCancel(cmd.Context())
		defer cancelFunc()

		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(ProxiroProxy, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		targetAddr := getString(ProxiroTarget, targetAddrFlag)
		if targetAddr == "" {
			return fmt.Errorf("required flag --target-addr is missing")
		}

		_, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return err
		}

		result := make(chan error, 2)

		onConnect := func(ctx context.Context, addr string) error {
			defer cancelFunc()

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				result <- err
				return err
			}

			var sargs []string
			sargs = append(sargs, "-p", port, host)
			sargs = append(sargs, "-o", fmt.Sprintf("HostKeyAlias=%s", targetAddr))
			if userName != "" {
				sargs = append(sargs, "-l", userName)
			}

			ecmd := exec.Command("ssh", sargs...)
			ecmd.Stdin = os.Stdin
			ecmd.Stdout = os.Stdout
			ecmd.Stderr = os.Stderr
			err = ecmd.Run()
			result <- err
			return err
		}

		if err := client.StartClient(cancelCtx, proxyAddr, 0, targetAddr, caFile, tlsSkipVerify, onConnect); err != nil {
			return err
		}

		return <-result
	}

	return command
}
