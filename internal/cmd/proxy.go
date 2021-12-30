package cmd

import (
	"github.com/jsiebens/proxiro/internal/config"
	"github.com/jsiebens/proxiro/internal/server"
	"github.com/spf13/cobra"
)

func proxyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "proxy",
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *cobra.Command, args []string) error {
		c, err := config.LoadConfig(configFile)
		if err != nil {
			return err
		}
		return server.StartProxy(c)
	}

	return command
}
