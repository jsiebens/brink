package cmd

import (
	"fmt"
	"github.com/jsiebens/brink/internal/version"
	"github.com/muesli/coral"
)

func versionCommand() *coral.Command {
	var command = &coral.Command{
		Use:          "version",
		Short:        "Display version information",
		SilenceUsage: true,
	}

	command.Run = func(cmd *coral.Command, args []string) {
		clientVersion, clientRevision := version.GetReleaseInfo()
		fmt.Printf(`
 Version:       %s 
 Git Revision:  %s

`, clientVersion, clientRevision)
	}

	return command
}
