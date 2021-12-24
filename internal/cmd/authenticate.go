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
		SilenceUsage: true,
	}

	var proxyAddrFlag string
	var tlsSkipVerify bool
	var caFile string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")
	command.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "")
	command.Flags().StringVar(&caFile, "ca-file", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		logrus.SetOutput(ioutil.Discard)

		proxyAddr := getString(ProxiroProxy, proxyAddrFlag)
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
		SilenceUsage: true,
	}

	var proxyAddrFlag string

	command.Flags().StringVarP(&proxyAddrFlag, "proxy-addr", "r", "", "")

	command.RunE = func(cmd *cobra.Command, args []string) error {
		proxyAddr := getString(ProxiroProxy, proxyAddrFlag)
		if proxyAddr == "" {
			return fmt.Errorf("required flag --proxy-addr is missing")
		}

		url, err := util.NormalizeProxyUrl(proxyAddr)
		if err != nil {
			return err
		}
		_ = client.DeleteAuthToken(url.String())

		return nil
	}

	return command
}
