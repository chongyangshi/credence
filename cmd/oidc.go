package cmd

import (
	"github.com/spf13/cobra"

	"github.com/chongyangshi/credence/oidc"
)

var (
	oidcCmd = &cobra.Command{
		Use:   "oidc",
		Short: "Request credentials for the given cluster using OIDC",

		RunE: oidc.Login,
	}
)

func init() {
	oidcCmd.Flags().String(oidc.OIDCIssuer, "", "The URL to the OIDC issuer / authorization server of your cluster, e.g. https://example.okta.com/oauth2/default")
	oidcCmd.MarkFlagRequired(oidc.OIDCIssuer)

	oidcCmd.Flags().String(oidc.OIDCIssuerAuthorizePath, "/v1/authorize", "The authorization code endpoint URI for the OIDC issuer / authorization server of your cluster")
	oidcCmd.Flags().String(oidc.OIDCIssuerTokenPath, "/v1/token", "The token code endpoint URI for the OIDC issuer / authorization server of your cluster")
	oidcCmd.Flags().String(oidc.OIDCIssuerCA, "", "Path to a file containing non-system CA certificates to be trusted for the OIDC issuer / authorization server, using system CA pool by default")

	oidcCmd.Flags().String(oidc.OIDCClientID, "", "The client ID for the OIDC issuer / authorization server of your cluster")
	oidcCmd.MarkFlagRequired(oidc.OIDCClientID)

	oidcCmd.Flags().String(oidc.OIDCCallbackAddr, "127.0.0.1:18000", "The local host:port for receiving authorization code callback from the OIDC issuer / authorization server")
	oidcCmd.Flags().String(oidc.OIDCCallbackAuthorizePath, "/login/callback", "The local path for receiving authorization code  callback from the OIDC issuer / authorization server")

	rootCmd.AddCommand(oidcCmd)
}
