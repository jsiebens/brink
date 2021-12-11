package main

import (
	"fmt"
	"github.com/jsiebens/proxiro/internal/auth"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/spf13/cobra"
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
		Use:          "connect",
		SilenceUsage: true,
		Args:         cobra.MinimumNArgs(1),
		ArgAliases:   []string{"target"},
	}

	var listeners []string
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringSliceVarP(&listeners, "listen-addr", "l", []string{}, "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		return client.StartClient(cmd.Context(), args[0], listeners, caFile, tlsSkipVerify)
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
