package keychain

import (
	"encoding/base64"
	"fmt"

	"github.com/keybase/go-keychain"
	"github.com/tstranex/u2f"
)

const (
	keychainRegistrationsService = "credence-u2f"
)

func (k *KeychainStore) RetrieveRegistration(rawKeyhandle []byte) (*u2f.Registration, error) {
	keyhandle := encodeRawKeyhandle(rawKeyhandle)
	account := keyhandle
	label := getRegistrationID(keyhandle)

	payload, err := keychain.GetGenericPassword(keychainRegistrationsService, account, label, keychainAccessGroup)
	if err != nil {
		return nil, fmt.Errorf("error retrieving registration for %s: %+v", keyhandle, err)
	}

	// Existing registration not found, should be handled by the caller
	if payload == nil {
		return nil, nil
	}

	registration := u2f.Registration{}
	if err = registration.UnmarshalBinary(payload); err != nil {
		return nil, fmt.Errorf("error unmarshalling registration for %s: %+v", keyhandle, err)
	}

	return &registration, nil
}

func (k *KeychainStore) StoreRegistration(registration *u2f.Registration) error {
	keyhandle := encodeRawKeyhandle(registration.KeyHandle)

	payload, err := registration.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshalling registration for %s: %+v", keyhandle, err)
	}

	account := keyhandle
	label := getRegistrationID(keyhandle)

	// Check if registration already exists, we can overwrite any older registration of
	// the same type for the same hardware token, but we need to delete that explicitly.

	existing, err := keychain.GetGenericPassword(keychainRegistrationsService, account, label, keychainAccessGroup)
	if err != nil {
		return fmt.Errorf("error checking existence of registration for %s: %+v", account, err)
	}
	if existing != nil {
		// Found, delete existing registration
		if err = keychain.DeleteGenericPasswordItem(keychainRegistrationsService, account); err != nil {
			return fmt.Errorf("error overwriting existing registration for %s: %+v", account, err)
		}
	}

	item := keychain.NewGenericPassword(
		keychainRegistrationsService,
		account,
		label,
		payload,
		keychainAccessGroup,
	)
	item.SetSynchronizable(keychain.SynchronizableNo)

	return keychain.AddItem(item)
}

func getRegistrationID(keyhandle string) string {
	return fmt.Sprintf("credence:u2f:%s", keyhandle)
}

func encodeRawKeyhandle(rawKeyhandle []byte) string {
	return base64.RawURLEncoding.EncodeToString(rawKeyhandle)
}
