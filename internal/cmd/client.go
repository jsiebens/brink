package cmd

import (
	"context"
	"fmt"
	"github.com/jsiebens/brink/internal/client"
	"github.com/jsiebens/brink/internal/util"
	"github.com/muesli/coral"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/execabs"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

var (
	proxyAddrFlag string
	tlsSkipVerify bool
	caFile        string
	noBrowser     bool
	showQR        bool
)

func registerProxyFlags(command *coral.Command) {
	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", fmt.Sprintf("Addr of the Brink proxy. This can also be specified via the environment variable %s.", BrinkProxyAddr))
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Disable verification of TLS certificates, highly discouraged as it decreases the security of data transmissions.")
	command.Flags().StringVar(&caFile, "ca-file", "", "Path on the local disk to a single PEM-encoded CA certificate to verify the proxy or server SSL certificate.")
	command.Flags().BoolVar(&noBrowser, "no-browser", false, "Disable the usage of a browser, just print the login URL")
	command.Flags().BoolVar(&showQR, "qr", false, "Show QR code for login URLs")
}

func connectCommand() *coral.Command {
	command := &coral.Command{
		Use:          "connect",
		Short:        "Start a tunnel to a proxy for TCP forwarding through which another process can create a connection (eg. SSH, PostgreSQL) to a remote target.",
		SilenceUsage: true,
	}

	var targetAddrFlag string
	var listenPort uint64
	var listenOnStdin bool
	var execCommand string

	registerProxyFlags(command)
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "Addr of the remote target the connections should be tunneled to.")
	command.Flags().StringVarP(&execCommand, "exec", "e", "", "If set, after connecting to the worker, the given binary will be executed. This should be a binary on your path, or an absolute path.")
	command.Flags().Uint64VarP(&listenPort, "listen-port", "p", 0, "Port on which the client should bind and listen for connections that should be tunneled.")
	command.Flags().BoolVarP(&listenOnStdin, "listen-on-stdin", "W", false, "If true, the standard input and standard output on the client is forward to the target over the tunnel.")

	command.RunE = func(cmd *coral.Command, args []string) error {
		cancelCtx, cancelFunc := context.WithCancel(cmd.Context())
		defer cancelFunc()

		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(BrinkProxyAddr, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		targetAddr := getString(BrinkTargetAddr, targetAddrFlag)
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
			return client.StartClient(cancelCtx, proxyAddr, "-", targetAddr, caFile, tlsSkipVerify, noBrowser, showQR, nil)
		}

		if execCommand != "" {
			onConnect, result := execOnConnect(execCommand, noArgs, args, cancelFunc)

			if err := client.StartClient(cancelCtx, proxyAddr, fmt.Sprintf("127.0.0.1:%d", 0), targetAddr, caFile, tlsSkipVerify, noBrowser, showQR, onConnect); err != nil {
				return err
			}

			return <-result
		}

		return client.StartClient(cancelCtx, proxyAddr, fmt.Sprintf("127.0.0.1:%d", listenPort), targetAddr, caFile, tlsSkipVerify, noBrowser, showQR, printListenerInfo)
	}

	return command
}

func sshCommand() *coral.Command {
	command := &coral.Command{
		Use:          "ssh",
		Short:        "Start a tunnel to a proxy and launches a proxied ssh connection.",
		SilenceUsage: true,
	}

	var targetAddrFlag string
	var username string

	registerProxyFlags(command)
	command.Flags().StringVarP(&targetAddrFlag, "target-addr", "t", "", "Addr of the remote target the connections should be tunneled to.")
	command.Flags().StringVarP(&username, "username", "u", "", "Specifies the username to pass through to the client")

	command.RunE = func(cmd *coral.Command, args []string) error {
		cancelCtx, cancelFunc := context.WithCancel(cmd.Context())
		defer cancelFunc()

		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(BrinkProxyAddr, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		targetAddr := getString(BrinkTargetAddr, targetAddrFlag)
		if targetAddr == "" {
			return fmt.Errorf("required flag --target-addr is missing")
		}

		_, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return err
		}

		buildArgs := func(addr, ip, port string) (sshArgs []string) {
			sshArgs = append(sshArgs, "-p", port, ip)
			sshArgs = append(sshArgs, "-o", fmt.Sprintf("HostKeyAlias=brink:%s:%s", util.StripScheme(proxyAddr), targetAddr))
			if username != "" {
				sshArgs = append(sshArgs, "-l", username)
			}
			return
		}

		onConnect, result := execOnConnect("ssh", buildArgs, args, cancelFunc)

		if err := client.StartClient(cancelCtx, proxyAddr, fmt.Sprintf("127.0.0.1:%d", 0), targetAddr, caFile, tlsSkipVerify, noBrowser, showQR, onConnect); err != nil {
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
				fmt.Sprintf("{{brink.%s}}", typ),
				fmt.Sprintf("{{ brink.%s}}", typ),
				fmt.Sprintf("{{brink.%s }}", typ),
				fmt.Sprintf("{{ brink.%s }}", typ),
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

func printListenerInfo(ctx context.Context, addr, host, port string) error {
	fmt.Printf("\n  Listening on %s\n\n", addr)
	return nil
}
