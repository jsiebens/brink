package cmd

import (
	"github.com/jsiebens/proxiro/internal/auth"
	"github.com/spf13/cobra"
)

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