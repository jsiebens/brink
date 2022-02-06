package cmd

import (
	"github.com/muesli/coral"
	"os"
)

const (
	BrinkProxyAddr  = "BRINK_PROXY_ADDR"
	BrinkTargetAddr = "BRINK_TARGET_ADDR"
)

func Execute() error {
	rootCmd := &coral.Command{
		Use: "brink",
	}

	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(authCommand())
	rootCmd.AddCommand(connectCommand())
	rootCmd.AddCommand(sshCommand())
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
