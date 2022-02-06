package cmd

import (
	"github.com/spf13/cobra"

	"github.com/chongyangshi/credence/oidc"
)

func init() {
	oidcCmd.Flags().String("issuer", "", "The URL to the OIDC issuer / authorization server of your cluster, e.g. https://example.okta.com/oauth2/default")
	oidcCmd.MarkFlagRequired("issuer")

	oidcCmd.Flags().String("issuer-authorize-path", "/v1/authorize", "The URL authorization code endpoint for the OIDC issuer / authorization server of your cluster")
	oidcCmd.Flags().String("issuer-token-path", "/v1/token", "The URL token endpoint for the OIDC issuer / authorization server of your cluster")
	oidcCmd.Flags().String("issuer-ca", "", "Path to a file containing non-system CA certificates to be trusted for the OIDC issuer / authorization server, using system CA pool by default")

	oidcCmd.Flags().String("client-id", "", "The client ID for the OIDC issuer / authorization server of your cluster")
	oidcCmd.MarkFlagRequired("client-id")

	oidcCmd.Flags().String("callback-addr", "127.0.0.1:18000", "The local host:port for receiving callback from the OIDC issuer / authorization server")

	rootCmd.AddCommand(oidcCmd)
}

var (
	oidcCmd = &cobra.Command{
		Use:   "oidc",
		Short: "Request credentials for the given cluster using OIDC",

		RunE: oidc.Login,
	}

	oidcIssuerURL    string
	oidcClientID     string
	oidcCallbackAddr string
)
