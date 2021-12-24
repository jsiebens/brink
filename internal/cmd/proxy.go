package cmd

import (
	"github.com/jsiebens/proxiro/internal/proxy"
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
		c, err := proxy.LoadConfig(configFile)
		if err != nil {
			return err
		}

		return proxy.StartServer(c)
	}

	return command
}
