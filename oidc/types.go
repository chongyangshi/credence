package oidc

import (
	"fmt"
	"net/url"
	"path"
)

// Used for message passing to OIDC provider only
type OIDCAuthorizeRequest struct {
	ClientID     string
	Nonce        string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        string

	// Required PKCE fields
	CodeChallenge        string
	CodeChallengeMedthod string
}

func (r OIDCAuthorizeRequest) ToURLParams(issuer url.URL, authorizePath string) string {
	issuer.Path = fmt.Sprintf("%s%s", issuer.Path, path.Clean(authorizePath))

	queryParams := url.Values{}
	queryParams.Add("client_id", r.ClientID)
	queryParams.Add("nonce", r.Nonce)
	queryParams.Add("redirect_uri", r.RedirectURI)
	queryParams.Add("response_type", r.ResponseType)
	queryParams.Add("state", r.State)
	queryParams.Add("scope", r.Scope)
	queryParams.Add("code_challenge", r.CodeChallenge)
	queryParams.Add("code_challenge_method", r.CodeChallengeMedthod)
	issuer.RawQuery = queryParams.Encode()

	return issuer.String()
}

// Used for message passing from HTTP server only
type OIDCAuthorizeResponse struct {
	Code  string
	State string
	Error error
}

type OIDCTokenRequest struct {
	ClientID     string `form:"client_id"`
	Code         string `form:"code"`
	GrantType    string `form:"grant_type"`
	RedirectURI  string `form:"redirect_uri,omitempty"`
	RefreshToken string `form:"refresh_token,omitempty"`

	// Required PKCE fields
	CodeVerifier string `form:"code_verifier"`
}

func (r OIDCTokenRequest) ToFormData() string {
	formData := url.Values{}

	formData.Add("client_id", r.ClientID)
	formData.Add("code", r.Code)
	formData.Add("grant_type", r.GrantType)

	if r.RedirectURI != "" {
		formData.Add("redirect_uri", r.RedirectURI)
	}

	if r.RefreshToken != "" {
		formData.Add("refresh_token", r.RefreshToken)
	}

	formData.Add("code_verifier", r.CodeVerifier)

	return formData.Encode()
}

type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        error
}
