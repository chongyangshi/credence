package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
)

const (
	pkceChallengeType = "S256"
	challengeLength   = 64

	scopeOfflineAccess = "offline_access"
)

var (
	// !!! Hard-coded user configuration section
	// These OIDC scopes need to be configured with your authorization server
	// so that the ID token generated will only contain a corresponding claim
	// if they are requested explicitly. These values are not configurable via
	// the client as the values hardcoded into the binary for keychain access
	// authorization is part of the security model of credence. If you need
	// different scope names, you should compile and distribute your own
	// version of credence after modifying them here.
	scopePrivilegedActions = "kubernetes_privileged_actions"
	scopeRegularActions    = "kubernetes_regular_actions"

	scopeIsSensitive = map[string]bool{
		scopePrivilegedActions: true,
		scopeRegularActions:    false,
	}
)

func Login(cmd *cobra.Command, args []string) error {
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

	log.Printf("Authorizing unprivileged access via %s...", config.Issuer)
	unprivilegedRsp, err := authorize(&config, scopes)
	if err != nil {
		log.Printf("Error authorizing unprivileged access via %s: %+v", config.Issuer, err)
		return err
	}

	scopes = append(scopes, scopePrivilegedActions)
	log.Printf("Authorizing privileged access via %s...", config.Issuer)
	privilegedRsp, err := authorize(&config, scopes)
	if err != nil {
		log.Printf("Error authorizing privileged access via %s: %+v", config.Issuer, err)
		return err
	}

	fmt.Println(&config, unprivilegedRsp.RefreshToken, []string{"openid", scopeRegularActions})
	fmt.Println(&config, privilegedRsp.RefreshToken, scopes)
	return nil
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

func generateStateAndNonce() (string, string, error) {
	randBuffer := make([]byte, challengeLength)
	_, err := rand.Read(randBuffer)
	if err != nil {
		return "", "", err
	}

	state := hex.EncodeToString(randBuffer[0 : challengeLength/2])
	nonce := hex.EncodeToString(randBuffer[challengeLength/2:])

	return state, nonce, nil
}

func generatePKCEChallenge() (string, string, error) {
	randBuffer := make([]byte, challengeLength)
	_, err := rand.Read(randBuffer)
	if err != nil {
		return "", "", err
	}

	verifier := hex.EncodeToString(randBuffer)

	h := sha256.New()
	_, err = h.Write([]byte(verifier))
	if err != nil {
		return "", "", err
	}

	challengeCode := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return challengeCode, verifier, nil
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
