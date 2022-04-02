package fido

import (
	"crypto/rand"
	"encoding/hex"
)

const (
	u2fChallengeLength = 64
)

func generateU2FChallenge() (string, error) {
	randBuffer := make([]byte, u2fChallengeLength)
	_, err := rand.Read(randBuffer)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randBuffer), nil
}
