package oidc

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultCallbackHost string = "127.0.0.1"
	defaultCallbackPort int64  = 18000
)

// A simple HTTP server for receiving callbacks from the OIDC provider.
// While the callback endpoint is unencrypted, it does not compromise the
// security model because the initial authorization code call is made to
// the OIDC provider via TLS, and thus any local intercepting attacks will
// not have access to the correct OAuth state for the client to process,
// and any authorization code controlled by the attacker cannot be redeemed
// wuth the OIDC provider due to PKCE validation.

func serveCallbackServer(hostAndPort string, srv *http.Server, responseChan chan OIDCAuthorizeResponse) error {
	host := defaultCallbackHost
	port := defaultCallbackPort

	var err error
	hostPortSplit := strings.SplitN(strings.TrimSpace(hostAndPort), ":", 2)
	if len(hostPortSplit) > 1 {
		host = hostPortSplit[0]
		port, err = strconv.ParseInt(hostPortSplit[1], 10, 32)
		if err != nil {
			return fmt.Errorf("malformed port: %s", hostPortSplit[1])
		}
	} else {
		port, err = strconv.ParseInt(hostPortSplit[0], 10, 32)
		if err != nil {
			return fmt.Errorf("malformed port: %s", hostPortSplit[1])
		}
	}

	if host != "127.0.0.1" && host != "localhost" {
		return fmt.Errorf("the callback server can only listen on 127.0.0.1 or localhost")
	}

	hostAndPort = fmt.Sprintf("%s:%d", host, port)
	mux := http.NewServeMux()
	srv.Addr = hostAndPort
	srv.Handler = mux

	mux.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		var response = OIDCAuthorizeResponse{}

		code := r.URL.Query().Get("code")
		if code == "" {
			response.Error = fmt.Errorf("expected authorization code not present or duplicated in callback: %+v", r.URL.Query())
			responseChan <- response
		} else {
			response.Code = code
		}

		state := r.URL.Query().Get("state")
		if state == "" {
			response.Error = fmt.Errorf("expected authorization state not present or duplicated in callback: %+v", r.URL.Query())
			responseChan <- response
		} else {
			response.State = state
		}

		w.WriteHeader(http.StatusOK)
		if _, err = fmt.Fprint(w, "Received OAuth login response, you can now close this page and return to the command line."); err != nil {
			response.Error = fmt.Errorf("error writing callback response: %+v", err)
		}

		responseChan <- response
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error shutting down authorize callback server: %+v", err)
		}
	}()

	return nil
}
