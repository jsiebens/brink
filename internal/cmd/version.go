package cmd

import (
	"fmt"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/spf13/cobra"
)

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
