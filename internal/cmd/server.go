package cmd

import (
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/server"
	"github.com/spf13/cobra"
)

func serverCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "server",
		Short:        "Start a server (and optionally a proxy) with a configuration file.",
		SilenceUsage: true,
	}

	var configFile string

	command.Flags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")

	command.RunE = func(command *cobra.Command, args []string) error {
		c, err := config.LoadConfig(configFile)
		if err != nil {
			return err
		}
		return server.StartServer(c)
	}

	return command
}
