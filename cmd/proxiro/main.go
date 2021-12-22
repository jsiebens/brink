package main

import (
	"fmt"
	"github.com/jsiebens/proxiro/internal/auth"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/spf13/cobra"
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
		Args:         cobra.ExactArgs(2),
		ArgAliases:   []string{"proxy", "target"},
	}

	var listenPort uint64
	var listenOnStdin bool
	var tlsSkipVerify bool
	var caFile string

	command.Flags().Uint64Var(&listenPort, "listen-port", 0, "")
	command.Flags().BoolVar(&listenOnStdin, "listen-on-stdin", false, "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		_, _, err := net.SplitHostPort(args[1])
		if err != nil {
			return err
		}

		if !listenOnStdin {
			return client.StartClient(cmd.Context(), args[0], listenPort, args[1], caFile, tlsSkipVerify, nil)
		} else {
			return client.StartClient(cmd.Context(), args[0], listenPort, args[1], caFile, tlsSkipVerify, client.StartNC)
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
