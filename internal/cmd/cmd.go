package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

const (
	ProxiroProxy  = "PROXIRO_PROXY"
	ProxiroTarget = "PROXIRO_TARGET"
)

func Execute() error {
	rootCmd := &cobra.Command{
		Use: "proxiro",
	}

	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(proxyCommand())
	rootCmd.AddCommand(authenticateCommand())
	rootCmd.AddCommand(connectCommand())
	rootCmd.AddCommand(sshCommand())
	rootCmd.AddCommand(logoutCommand())
	rootCmd.AddCommand(versionCommand())

	return rootCmd.Execute()
}

func getString(key, override string) string {
	if len(override) != 0 {
		return override
	}
	value := os.Getenv(key)
	if len(value) != 0 {
		return value
	}
	return ""
}
