package cmd

import (
	"fmt"
	"github.com/jsiebens/proxiro/internal/client"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
)

func authenticateCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "authenticate",
		Short:        "Authenticate the Proxiro Client for a specific Proxy.",
		SilenceUsage: true,
	}

	registerProxyFlags(command)

	command.RunE = func(cmd *cobra.Command, args []string) error {
		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(ProxiroProxyAddr, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		return client.Authenticate(cmd.Context(), proxyAddr, caFile, tlsSkipVerify)
	}

	return command
}

func logoutCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "logout",
		Short:        "Delete the current token from the local store.",
		SilenceUsage: true,
	}

	registerProxyFlags(command)

	command.RunE = func(cmd *cobra.Command, args []string) error {
		proxyAddr := getString(ProxiroProxyAddr, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		url, err := util.NormalizeHttpUrl(proxyAddr)
		if err != nil {
			return err
		}
		_ = client.DeleteAuthToken(url.String())

		return nil
	}

	return command
}
