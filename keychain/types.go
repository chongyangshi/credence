package keychain

import (
	"encoding/json"
	"fmt"
)

const (
	CredentialsTypePrivileged   = "privileged"
	CredentialsTypeUnprivileged = "unprivileged"
)

// KubernetesCredentials represents OIDC tokens issued for access to
type KubernetesCredentials struct {
	Cluster         string `json:"cluster"`
	ExpectedExpiry  string `json:"expected_expiry"`
	CredentialsType string `json:"credentials_type"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`

	// KeyHandle from U2F is set by the package for privileged credentials only
	KeyHandle string `json:"keyhandle"`
}

func (c *KubernetesCredentials) ToKeychainPayload() ([]byte, error) {

	if c.Cluster == "" {
		return nil, fmt.Errorf("unexpected unset cluster name for credentials")
	}

	if c.AccessToken == "" {
		return nil, fmt.Errorf("unexpected empty access token for credentials of %s", c.Cluster)
	}

	payloadBytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	return payloadBytes, nil
}

func credentialsfromKeychainPayload(payload []byte) (*KubernetesCredentials, error) {
	credentials := &KubernetesCredentials{}

	err := json.Unmarshal(payload, credentials)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}
