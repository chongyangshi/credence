package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/chongyangshi/credence/fido"
	"github.com/chongyangshi/credence/keychain"
)

const (
	pkceChallengeType = "S256"
	challengeLength   = 64

	scopeOfflineAccess = "offline_access"
)

func Login(cmd *cobra.Command, args []string) error {
	fidoRegistration, err := fido.RegisterHardwareToken(overrideDeviceAttestationCAPool)
	if err != nil {
		return err
	}

	authenticateResponse, err := fido.AuthenticateHardwareToken(fidoRegistration)
	if err != nil {
		return err
	}

	authenticateRsp, _ := json.Marshal(authenticateResponse)
	fmt.Println(string(authenticateRsp))

	// @TODO: write this into the credential circuit
	return nil

	config := OIDCConfig{}
	if err := config.FromCobraCommand(cmd); err != nil {
		return fmt.Errorf("error parsing OIDC config flags: %+v", err)
	}

	scopes := []string{"openid", scopeRegularActions}
	if config.IssuerUserScope != "" {
		scopes = append(scopes, config.IssuerUserScope)
	}
	if config.OfflineAccess {
		scopes = append(scopes, scopeOfflineAccess)
	}

	if err := doLogin(config.KubernetesClusterID, keychain.CredentialsTypeUnprivileged, &config, scopes); err != nil {
		log.Printf("Error authorizing %s access via %s...", keychain.CredentialsTypeUnprivileged, config.Issuer)
		return err
	}

	scopes = append(scopes, scopePrivilegedActions)
	if err := doLogin(config.KubernetesClusterID, keychain.CredentialsTypePrivileged, &config, scopes); err != nil {
		log.Printf("Error authorizing %s access via %s...", keychain.CredentialsTypePrivileged, config.Issuer)
		return err
	}

	return nil
}

// doLogin performs the OIDC login if the credentials cached in system keychain have expired,
// or if explicitly requested by the reauth flag in CLI.
func doLogin(clusterID, credentialsType string, config *OIDCConfig, scopes []string) error {

	credentialStore := keychain.KeychainStore{}

	// Check if we have existing credentials we can re-use or refresh access with
	existing, err := credentialStore.RetrieveCredentials(config.KubernetesClusterID, credentialsType)
	if err != nil {
		log.Printf("Error loading existing credentials for %s: %+v", clusterID, err)
		return err
	}

	credentials, reuse := canReuseCredentials(existing, config, scopes)
	if !reuse {
		// If we can't or don't have an existing valid credentials to re-use, request
		// a new session via OIDC.
		log.Printf("Authorizing %s access to %s via %s...", credentialsType, clusterID, config.Issuer)

		timeOfRequest := time.Now()
		rsp, err := authorize(config, scopes)
		if err != nil {
			log.Printf("Error authorizing %s access via %s: %+v", credentialsType, config.Issuer, err)
			return err
		}

		expectedExpiry, err := getExpectedExpiry(timeOfRequest, rsp.ExpiresIn)
		if err != nil {
			log.Printf("Error parsing %s access expiry for %s: %+v", credentialsType, clusterID, err)
			return err
		}

		credentials = &keychain.KubernetesCredentials{
			Cluster:         config.KubernetesClusterID,
			ExpectedExpiry:  expectedExpiry.Format(time.RFC3339),
			CredentialsType: credentialsType,
			AccessToken:     rsp.AccessToken,
			RefreshToken:    rsp.RefreshToken,
		}
	} else {
		log.Printf("Using existing token for %s access to %s...", credentialsType, clusterID)
	}

	// Store the new or existing valid credentials in system keychain
	if err = credentialStore.StoreCredentials(credentials); err != nil {
		log.Printf(
			"Error storing %s access credentials via %s for %s: %+v",
			credentialsType,
			config.Issuer,
			clusterID,
			err,
		)
		return err
	}

	return nil
}

// Check if we can re-use the provided credentials, also returns refreshed credentials
// if refreshToken is present and valid for use.
func canReuseCredentials(credentials *keychain.KubernetesCredentials, config *OIDCConfig, scopes []string) (*keychain.KubernetesCredentials, bool) {
	// Reauth explicitly requested via CLI
	if config.KubernetesReauth {
		return nil, false
	}

	// Existing credentials not found
	if credentials == nil {
		return nil, false
	}

	expectedExpiry, err := time.Parse(time.RFC3339, credentials.ExpectedExpiry)
	if err != nil {
		// Unexpected invalid expiry time estimate recorded, re-auth
		return nil, false
	}

	// Credentials should be unexpired, we can re-use. If this fails the user will need to
	// set the reauth flag and call again.
	if time.Now().Before(expectedExpiry) {
		return credentials, true
	}

	// Access token expired, but we may still be able to use refresh token if set
	if credentials.RefreshToken == "" {
		return nil, false
	}

	// Attempt to refresh, if we fail we must start reauth all over again
	timeOfRequest := time.Now()
	rsp, err := refresh(config, credentials.RefreshToken, scopes)
	if err != nil {
		log.Printf(
			"failed to refresh %s token for %s: %+v, trying reauth",
			credentials.CredentialsType,
			credentials.Cluster,
			err,
		)

		return nil, false
	}

	// Successfully refreshed access, return new credentials
	refreshExpiry, err := getExpectedExpiry(timeOfRequest, rsp.ExpiresIn)
	if err != nil {
		log.Printf(
			"Error parsing %s refresh expiry for %s: %+v",
			credentials.CredentialsType,
			credentials.Cluster,
			err,
		)
		return nil, false
	}

	newCredentials := &keychain.KubernetesCredentials{
		Cluster:         config.KubernetesClusterID,
		ExpectedExpiry:  refreshExpiry.Format(time.RFC3339),
		CredentialsType: credentials.CredentialsType,
		AccessToken:     rsp.AccessToken,
		RefreshToken:    rsp.RefreshToken,
	}
	return newCredentials, true
}

func authorize(config *OIDCConfig, scopes []string) (*OIDCTokenResponse, error) {
	state, nonce, err := generateStateAndNonce()
	if err != nil {
		return nil, err
	}

	challengeCode, verifier, err := generatePKCEChallenge()
	if err != nil {
		return nil, err
	}

	authorizeResponseChan := make(chan OIDCAuthorizeResponse)
	authorizeResponseSrv := &http.Server{}
	go func() {
		err = serveCallbackServer(config.CallbackAddr, authorizeResponseSrv, authorizeResponseChan)
		if err != nil {
			log.Printf("Error serving authorization callback: %+v", err)
		}
	}()

	authorizeURL := OIDCAuthorizeRequest{
		ClientID:     config.ClientID,
		Nonce:        nonce,
		RedirectURI:  fmt.Sprintf("http://%s/login/callback", config.CallbackAddr),
		ResponseType: "code",
		Scope:        strings.Join(scopes, " "),
		State:        state,

		CodeChallenge:        challengeCode,
		CodeChallengeMedthod: pkceChallengeType,
	}.ToURLParams(*config.Issuer, config.IssuerAuthorizePath)
	err = browser.OpenURL(authorizeURL)
	if err != nil {
		return nil, err
	}

	authorizeRsp := <-authorizeResponseChan
	if authorizeRsp.Error != nil {
		return nil, fmt.Errorf("received error from authorization callback server: %+v", authorizeRsp.Error)
	}

	err = authorizeResponseSrv.Shutdown(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error while shutting down authorization callback server: %+v", err)
	}

	tokenClient, err := getTokenClient(config.IssuerCAPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create client for token exchange: %+v", err)
	}

	tokenRequest := OIDCTokenRequest{
		ClientID:     config.ClientID,
		Code:         authorizeRsp.Code,
		GrantType:    "authorization_code",
		RedirectURI:  fmt.Sprintf("http://%s/login/callback", config.CallbackAddr),
		CodeVerifier: verifier,
	}
	tokenURL := fmt.Sprintf("%s%s", config.Issuer.String(), config.IssuerTokenPath)
	tokenData := tokenRequest.ToFormData()
	tokenReq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(tokenData))
	if err != nil {
		return nil, fmt.Errorf("error building token request: %+v", err)
	}
	tokenReq.Header.Add("Accept", "application/json")
	tokenReq.Header.Add("Cache-Control", "no-cache")
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rawRsp, err := tokenClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("error making token request: %+v", err)
	}

	rspBytes, err := ioutil.ReadAll(rawRsp.Body)
	defer rawRsp.Body.Close()

	if rawRsp.StatusCode < http.StatusOK || rawRsp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("received bad response from OIDC server (%d): %v", rawRsp.StatusCode, string(rspBytes))
	}

	rsp := OIDCTokenResponse{}
	err = json.Unmarshal(rspBytes, &rsp)
	if err != nil {
		return nil, fmt.Errorf("error parsing token response: %+v", err)
	}

	return &rsp, nil
}

func refresh(config *OIDCConfig, refreshToken string, scopes []string) (*OIDCTokenResponse, error) {
	tokenClient, err := getTokenClient(config.IssuerCAPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create client for token exchange: %+v", err)
	}

	tokenRequest := OIDCTokenRequest{
		ClientID:     config.ClientID,
		RefreshToken: refreshToken,
		GrantType:    "refresh_token",
		Scope:        strings.Join(scopes, " "),
	}
	tokenURL := fmt.Sprintf("%s%s", config.Issuer.String(), config.IssuerTokenPath)
	tokenData := tokenRequest.ToFormData()
	tokenReq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(tokenData))
	if err != nil {
		return nil, fmt.Errorf("error building refresh token request: %+v", err)
	}
	tokenReq.Header.Add("Accept", "application/json")
	tokenReq.Header.Add("Cache-Control", "no-cache")
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rawRsp, err := tokenClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("error making refresh token request: %+v", err)
	}

	rspBytes, err := ioutil.ReadAll(rawRsp.Body)
	defer rawRsp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("error reading token response: %+v", err)
	}

	if rawRsp.StatusCode < http.StatusOK || rawRsp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("received bad response from OIDC server (%d): %v", rawRsp.StatusCode, string(rspBytes))
	}

	rsp := OIDCTokenResponse{}
	err = json.Unmarshal(rspBytes, &rsp)
	if err != nil {
		return nil, fmt.Errorf("error parsing token response: %+v", err)
	}

	return &rsp, nil
}

func getTokenClient(issuerCAPath string) (*http.Client, error) {
	var caCertPool *x509.CertPool
	if issuerCAPath != "" {
		issuerCABytes, err := ioutil.ReadFile(issuerCAPath)
		if err != nil {
			return nil, fmt.Errorf("error reading CAs from file %s: %+v", issuerCAPath, err)
		}

		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(issuerCABytes); !ok {
			return nil, fmt.Errorf("failed to parse CAs from file %s", issuerCAPath)
		}
	} else {
		var err error
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error reading system CA pool: %v", err)
		}
	}

	tokenClient := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    caCertPool,
			},
		},
	}

	return tokenClient, nil
}
