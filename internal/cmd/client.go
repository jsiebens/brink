package cmd

import (
	"context"
	"fmt"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/execabs"
	"io/ioutil"
	"net"
	"os"
	"strings"
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
	var execCommand string
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "")
	command.Flags().StringVarP(&execCommand, "exec", "e", "", "")
	command.Flags().Uint64Var(&listenPort, "listen-port", 0, "")
	command.Flags().BoolVar(&listenOnStdin, "listen-on-stdin", false, "")
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

		if listenOnStdin && execCommand != "" {
			return fmt.Errorf("flags --listen-on-stdin and --exec are mutually exclusive")
		}

		_, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return err
		}

		if listenOnStdin {
			return client.StartClient(cancelCtx, proxyAddr, 0, targetAddr, caFile, tlsSkipVerify, client.StartNC)
		}

		if execCommand != "" {
			onConnect, result := execOnConnect(execCommand, noArgs, args, cancelFunc)

			if err := client.StartClient(cancelCtx, proxyAddr, 0, targetAddr, caFile, tlsSkipVerify, onConnect); err != nil {
				return err
			}

			return <-result
		}

		return client.StartClient(cancelCtx, proxyAddr, listenPort, targetAddr, caFile, tlsSkipVerify, client.PrintListenerInfo)
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
	var username string
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "")
	command.Flags().StringVarP(&username, "username", "u", "", "")
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

		buildArgs := func(addr, ip, port string) (sshArgs []string) {
			sshArgs = append(sshArgs, "-p", port, ip)
			sshArgs = append(sshArgs, "-o", fmt.Sprintf("HostKeyAlias=%s", targetAddr))
			if username != "" {
				sshArgs = append(sshArgs, "-l", username)
			}
			return
		}

		onConnect, result := execOnConnect("ssh", buildArgs, args, cancelFunc)

		if err := client.StartClient(cancelCtx, proxyAddr, 0, targetAddr, caFile, tlsSkipVerify, onConnect); err != nil {
			return err
		}

		return <-result
	}

	return command
}

func execOnConnect(cmd string, buildArgs func(addr string, ip string, port string) []string, passthroughArgs []string, cancel context.CancelFunc) (client.OnConnect, chan error) {
	result := make(chan error, 2)
	return func(ctx context.Context, addr, ip, port string) error {
		defer cancel()

		stringReplacer := func(in, typ, replacer string) string {
			for _, style := range []string{
				fmt.Sprintf("{{proxiro.%s}}", typ),
				fmt.Sprintf("{{ proxiro.%s}}", typ),
				fmt.Sprintf("{{proxiro.%s }}", typ),
				fmt.Sprintf("{{ proxiro.%s }}", typ),
			} {
				in = strings.Replace(in, style, replacer, -1)
			}
			return in
		}

		var args []string
		args = append(buildArgs(addr, ip, port))
		args = append(passthroughArgs, args...)

		for i := range args {
			args[i] = stringReplacer(args[i], "port", port)
			args[i] = stringReplacer(args[i], "ip", ip)
			args[i] = stringReplacer(args[i], "addr", addr)
		}

		ecmd := execabs.Command(cmd, args...)
		ecmd.Stdin = os.Stdin
		ecmd.Stdout = os.Stdout
		ecmd.Stderr = os.Stderr
		err := ecmd.Run()
		result <- err
		return err
	}, result
}

func noArgs(addr, ip, port string) []string {
	return []string{}
}
