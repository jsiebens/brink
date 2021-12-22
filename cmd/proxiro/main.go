package main

import (
	"context"
	"fmt"
	"github.com/jsiebens/proxiro/internal/auth"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net"
	"os"
)

func main() {
	cmd := rootCommand()
	cmd.AddCommand(serverCommand())
	cmd.AddCommand(proxyCommand())
	cmd.AddCommand(connectCommand())
	cmd.AddCommand(versionCommand())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	return &cobra.Command{
		Use: "proxiro",
	}
}

func serverCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "server",
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *cobra.Command, args []string) error {
		c, err := auth.LoadConfig(configFile)
		if err != nil {
			return err
		}

		return auth.StartServer(c)
	}

	return command
}

func proxyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "proxy",
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *cobra.Command, args []string) error {
		c, err := proxy.LoadConfig(configFile)
		if err != nil {
			return err
		}

		return proxy.StartServer(c)
	}

	return command
}

func connectCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "connect [proxy] [target]",
		SilenceUsage: true,
	}

	var proxyAddr string
	var targetAddr string
	var listenPort uint64
	var listenOnStdin bool
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddr, "proxy-addr", "r", "", "")
	command.Flags().StringVarP(&targetAddr, "target-addr", "t", "", "")
	command.Flags().Uint64Var(&listenPort, "listen-port", 0, "")
	command.Flags().BoolVar(&listenOnStdin, "listen-on-stdin", false, "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	_ = command.MarkFlagRequired("proxy-addr")
	_ = command.MarkFlagRequired("target-addr")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		logrus.SetOutput(ioutil.Discard)

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

func versionCommand() *cobra.Command {
	var command = &cobra.Command{
		Use:          "version",
		Short:        "Display version information",
		SilenceUsage: true,
	}

	command.Run = func(cmd *cobra.Command, args []string) {
		clientVersion, clientRevision := version.GetReleaseInfo()
		fmt.Printf(`
 Version:       %s 
 Git Revision:  %s

`, clientVersion, clientRevision)
	}

	return command
}
