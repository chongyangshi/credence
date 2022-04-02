package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

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

func getExpectedExpiry(timeOfRequest time.Time, expiresInSeconds int) (*time.Time, error) {
	if expiresInSeconds <= 0 {
		return nil, fmt.Errorf("unexpected negative or zero expiry time: %d", expiresInSeconds)
	}

	expiryDuration := time.Duration(expiresInSeconds) * time.Second
	expectedExpiry := timeOfRequest.Add(expiryDuration)

	return &expectedExpiry, nil
}
