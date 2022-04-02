package keychain

import (
	"fmt"

	"github.com/keybase/go-keychain"
)

const (
	keychainService     = "credence-kubernetes"
	keychainAccessGroup = "credence"
)

type KeychainCredentialStore struct{}

func (k *KeychainCredentialStore) RetrieveCredentials(cluster, credentialsType string) (*KubernetesCredentials, error) {
	payload, err := keychain.GetGenericPassword(keychainService, cluster, credentialsType, keychainAccessGroup)
	if err != nil {
		return nil, err
	}

	credentials, err := credentialsfromKeychainPayload(payload)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// @TODO: handle credential overwrites.
func (k *KeychainCredentialStore) StoreCredentials(credentials *KubernetesCredentials) error {
	payload, err := credentials.ToKeychainPayload()
	if err != nil {
		return err
	}

	account := fmt.Sprintf("%s:%s", credentials.Cluster, credentials.CredentialsType)

	item := keychain.NewGenericPassword(
		keychainService,
		account,
		account,
		payload,
		keychainAccessGroup,
	)
	item.SetSynchronizable(keychain.SynchronizableNo)

	return keychain.AddItem(item)
}
