package cmd

import (
	"github.com/jsiebens/brink/internal/auth"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/proxy"
	"github.com/muesli/coral"
)

func serverCommand() *coral.Command {
	command := &coral.Command{
		Use:          "server",
		SilenceUsage: true,
	}

	command.AddCommand(serverAuthCommand())
	command.AddCommand(serverProxyCommand())

	return command
}

func serverAuthCommand() *coral.Command {
	return createServerCommand("auth", "Start an auth server with a configuration file.", auth.StartServer)
}

func serverProxyCommand() *coral.Command {
	return createServerCommand("proxy", "Start a proxy server with a configuration file.", proxy.StartServer)
}

func createServerCommand(use, short string, start func(*config.Config) error) *coral.Command {
	command := &coral.Command{
		Use:          use,
		Short:        short,
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *coral.Command, args []string) error {
		c, err := config.LoadConfig(configFile)
		if err != nil {
			return err
		}
		return start(c)
	}

	return command
}
