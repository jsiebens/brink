package cmd

import (
	"context"
	"github.com/jsiebens/brink/internal/auth"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/proxy"
	"github.com/spf13/cobra"
)

func serverCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "server",
		SilenceUsage: true,
	}

	command.AddCommand(serverAuthCommand())
	command.AddCommand(serverProxyCommand())

	return command
}

func serverAuthCommand() *cobra.Command {
	return createServerCommand("auth", "Start an auth server with a configuration file.", auth.StartServer)
}

func serverProxyCommand() *cobra.Command {
	return createServerCommand("proxy", "Start a proxy server with a configuration file.", proxy.StartServer)
}

func createServerCommand(use, short string, start func(context.Context, *config.Config) error) *cobra.Command {
	command := &cobra.Command{
		Use:          use,
		Short:        short,
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *cobra.Command, args []string) error {
		c, err := config.LoadConfig(configFile)
		if err != nil {
			return err
		}
		return start(command.Context(), c)
	}

	return command
}
