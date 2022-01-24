package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

const (
	BrinkProxyAddr  = "BRINK_PROXY_ADDR"
	BrinkTargetAddr = "BRINK_TARGET_ADDR"
)

func Execute() error {
	rootCmd := &cobra.Command{
		Use: "brink",
	}

	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(authenticateCommand())
	rootCmd.AddCommand(connectCommand())
	rootCmd.AddCommand(sshCommand())
	rootCmd.AddCommand(logoutCommand())
	rootCmd.AddCommand(keygenCommand())
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
