package oidc

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

const (
	// See cmd/oidc.go for documentation on these cli parameters
	OIDCIssuer              = "issuer"
	OIDCIssuerAuthorizePath = "issuer-authorize-path"
	OIDCIssuerTokenPath     = "issuer-token-path"
	OIDCIssuerCA            = "issuer-ca"
	OIDCIssuerUserScope     = "issuer-user-scope"

	OIDCClientID     = "client-id"
	OIDCRefreshToken = "refresh-token"

	OIDCCallbackAddr          = "callback-addr"
	OIDCCallbackAuthorizePath = "callback-authorize-path"
)

type OIDCConfig struct {
	Issuer              *url.URL
	IssuerAuthorizePath string
	IssuerTokenPath     string
	IssuerCAPath        string
	IssuerUserScope     string

	ClientID      string
	OfflineAccess bool

	CallbackAddr          string
	CallbackAuthorizePath string
}

func (o *OIDCConfig) FromCobraCommand(cmd *cobra.Command) error {
	issuerURL, err := cmd.Flags().GetString(OIDCIssuer)
	if err != nil {
		return err
	}

	o.Issuer, err = url.Parse(issuerURL)
	if err != nil {
		return err
	}

	if o.Issuer.Scheme != "https" {
		return fmt.Errorf("scheme of issuer URL must be TLS (https), got %s", o.Issuer.Scheme)
	}

	o.IssuerAuthorizePath, err = cmd.Flags().GetString(OIDCIssuerAuthorizePath)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(o.IssuerAuthorizePath, "/") {
		o.IssuerAuthorizePath = fmt.Sprintf("/%s", o.IssuerAuthorizePath)
	}

	o.IssuerTokenPath, err = cmd.Flags().GetString(OIDCIssuerTokenPath)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(o.IssuerTokenPath, "/") {
		o.IssuerTokenPath = fmt.Sprintf("/%s", o.IssuerTokenPath)
	}

	o.IssuerCAPath, err = cmd.Flags().GetString(OIDCIssuerCA)
	if err != nil {
		return err
	}

	o.OfflineAccess, err = cmd.Flags().GetBool(OIDCRefreshToken)
	if err != nil {
		return err
	}

	o.IssuerUserScope, err = cmd.Flags().GetString(OIDCIssuerUserScope)
	if err != nil {
		return err
	}

	o.CallbackAddr, err = cmd.Flags().GetString(OIDCCallbackAddr)
	if err != nil {
		return err
	}
	o.CallbackAddr = strings.TrimPrefix(o.CallbackAddr, "http://")

	o.ClientID, err = cmd.Flags().GetString(OIDCClientID)
	if err != nil {
		return err
	}

	return nil
}
