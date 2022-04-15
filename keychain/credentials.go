package keychain

import (
	"fmt"

	"github.com/keybase/go-keychain"
)

const (
	keychainCredentialsService = "credence-kubernetes"
)

func (k *KeychainStore) RetrieveCredentials(cluster, credentialsType string) (*KubernetesCredentials, error) {
	account := getKeychainAccount(cluster, credentialsType)
	label := getKeychainLabel(cluster, credentialsType)

	if credentialsType == CredentialsTypePrivileged {
		// @TODO
	}

	payload, err := keychain.GetGenericPassword(keychainCredentialsService, account, label, keychainAccessGroup)
	if err != nil {
		return nil, fmt.Errorf("error retrieving credentials for %s: %+v", account, err)
	}

	// Existing credentials not found, should be handled by the caller
	if payload == nil {
		return nil, nil
	}

	credentials, err := credentialsfromKeychainPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("error parsing credentials for %s: %+v", account, err)
	}

	return credentials, nil
}

func (k *KeychainStore) StoreCredentials(credentials *KubernetesCredentials) error {
	// Store a copy of the U2F keyhandle inside the secret payload for privileged credentials,
	// which is checked on retrieval to ensure it was the same key.
	if credentials.CredentialsType == CredentialsTypePrivileged {
		// @TODO
	}

	payload, err := credentials.ToKeychainPayload()
	if err != nil {
		return err
	}

	account := getKeychainAccount(credentials.Cluster, credentials.CredentialsType)
	label := getKeychainLabel(credentials.Cluster, credentials.CredentialsType)

	// Check if item already exists, we can overwrite any older credentials of
	// the same type for the same cluster, but we need to delete that explicitly.

	existing, err := keychain.GetGenericPassword(keychainCredentialsService, account, label, keychainAccessGroup)
	if err != nil {
		return fmt.Errorf("error checking existence of credentials for %s: %+v", account, err)
	}
	if existing != nil {
		// Found, delete existing item. There is a time-of-check/time-of-use risk if multiple
		// instances of credence are running at the same time, but re-running the failed
		// instance will fix it and it should happen rarely.
		if err = keychain.DeleteGenericPasswordItem(keychainCredentialsService, account); err != nil {
			return fmt.Errorf("error overwriting existing credentials for %s: %+v", account, err)
		}
	}

	item := keychain.NewGenericPassword(
		keychainCredentialsService,
		account,
		label,
		payload,
		keychainAccessGroup,
	)
	item.SetSynchronizable(keychain.SynchronizableNo)

	return keychain.AddItem(item)
}

func getKeychainAccount(cluster, credentialsType string) string {
	return fmt.Sprintf("%s:%s", cluster, credentialsType)
}

func getKeychainLabel(cluster, credentialsType string) string {
	return fmt.Sprintf("credence:%s:%s", cluster, credentialsType)
}
