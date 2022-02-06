package oidc

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
