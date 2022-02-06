package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
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
	issuerURL, err := cmd.Flags().GetString(OIDCIssuer)
	if err != nil {
		return err
	}

	issuerAuthorizePath, err := cmd.Flags().GetString(OIDCIssuerAuthorizePath)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(issuerAuthorizePath, "/") {
		issuerAuthorizePath = fmt.Sprintf("/%s", issuerAuthorizePath)
	}

	issuerTokenPath, err := cmd.Flags().GetString(OIDCIssuerTokenPath)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(issuerTokenPath, "/") {
		issuerTokenPath = fmt.Sprintf("/%s", issuerTokenPath)
	}

	issuerCAPath, err := cmd.Flags().GetString(OIDCIssuerCA)
	if err != nil {
		return err
	}

	offlineAccess, err := cmd.Flags().GetBool(OIDCRefreshToken)
	if err != nil {
		return err
	}

	issuerUserScope, err := cmd.Flags().GetString(OIDCIssuerUserScope)
	if err != nil {
		return err
	}

	callbackAddr, err := cmd.Flags().GetString(OIDCCallbackAddr)
	if err != nil {
		return err
	}
	callbackAddr = strings.TrimPrefix(callbackAddr, "http://")

	issuer, err := url.Parse(issuerURL)
	if err != nil {
		return err
	}

	if issuer.Scheme != "https" {
		return fmt.Errorf("scheme of issuer URL must be TLS (https), got %s", issuer.Scheme)
	}

	clientID, err := cmd.Flags().GetString(OIDCClientID)
	if err != nil {
		return err
	}

	state, nonce, err := generateStateAndNonce()
	if err != nil {
		return err
	}

	challengeCode, verifier, err := generatePKCEChallenge()
	if err != nil {
		return err
	}

	authorizeResponseChan := make(chan OIDCAuthorizeResponse)
	authorizeResponseSrv := &http.Server{}
	go func() {
		err = serveCallbackServer(callbackAddr, authorizeResponseSrv, authorizeResponseChan)
		if err != nil {
			log.Printf("Error serving authorization callback: %+v", err)
		}
	}()

	scopes := []string{"openid", scopePrivilegedActions, scopeRegularActions}
	if issuerUserScope != "" {
		scopes = append(scopes, issuerUserScope)
	}
	if offlineAccess {
		scopes = append(scopes, scopeOfflineAccess)
	}

	authorizeURL := OIDCAuthorizeRequest{
		ClientID:     clientID,
		Nonce:        nonce,
		RedirectURI:  fmt.Sprintf("http://%s/login/callback", callbackAddr),
		ResponseType: "code",
		Scope:        strings.Join(scopes, " "),
		State:        state,

		CodeChallenge:        challengeCode,
		CodeChallengeMedthod: pkceChallengeType,
	}.ToURLParams(*issuer, issuerAuthorizePath)
	err = browser.OpenURL(authorizeURL)
	if err != nil {
		return err
	}

	authorizeRsp := <-authorizeResponseChan
	if authorizeRsp.Error != nil {
		return fmt.Errorf("received error from authorization callback server: %+v", authorizeRsp.Error)
	}

	err = authorizeResponseSrv.Shutdown(context.Background())
	if err != nil {
		return fmt.Errorf("error while shutting down authorization callback server: %+v", err)
	}

	tokenClient, err := getTokenClient(issuerCAPath)
	if err != nil {
		return fmt.Errorf("cannot create client for token exchange: %+v", err)
	}

	tokenRequest := OIDCTokenRequest{
		ClientID:     clientID,
		Code:         authorizeRsp.Code,
		GrantType:    "authorization_code",
		RedirectURI:  fmt.Sprintf("http://%s/login/callback", callbackAddr),
		CodeVerifier: verifier,
	}
	tokenURL := fmt.Sprintf("%s%s", issuerURL, issuerTokenPath)
	tokenData := tokenRequest.ToFormData()
	tokenReq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(tokenData))
	if err != nil {
		return fmt.Errorf("error building token request: %+v", err)
	}
	tokenReq.Header.Add("Accept", "application/json")
	tokenReq.Header.Add("Cache-Control", "no-cache")
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tokenRsp, err := tokenClient.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("error making token request: %+v", err)
	}

	rsp, err := ioutil.ReadAll(tokenRsp.Body)
	defer tokenRsp.Body.Close()

	if tokenRsp.StatusCode < http.StatusOK || tokenRsp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("received bad response from OIDC server (%d): %v", tokenRsp.StatusCode, string(rsp))
	}

	fmt.Println(string(rsp))

	return nil
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
