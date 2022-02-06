package cmd

import (
	"fmt"
	"github.com/jsiebens/brink/internal/key"
	"github.com/muesli/coral"
)

func keygenCommand() *coral.Command {
	command := &coral.Command{
		Use:          "keygen",
		Short:        "",
		SilenceUsage: true,
	}

	command.RunE = func(cmd *coral.Command, args []string) error {
		privateKey, err := key.GeneratePrivateKey()
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Printf("  private key: %s\n", privateKey)
		fmt.Printf("   public key: %s\n", privateKey.Public())
		fmt.Println()

		return nil
	}

	return command
}
