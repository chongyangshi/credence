package fido

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	u2f "github.com/marshallbrekka/go-u2fhost"
	u2fhelper "github.com/tstranex/u2f"
)

// This implementation uses a mixture of (1) github.com/marshallbrekka/go-u2fhost
// ("u2f", by Marshall Brekka and others under the MIT License), which provides
// the command line interface with U2F devices but does not implement a parser
// for registration data; and (2) github.com/tstranex/u2f ("u2fhelper", by Timothy
// Stranex and others under the MIT License), which implements the registration
// parser but not the U2F command line interface.

const (
	u2fFaucetAndID = "http://localhost"
	pollInterval   = time.Millisecond * 250
)

type U2FRegistrationData struct {
	*u2f.RegisterResponse
	Version string
}

type U2FAuthenticationData struct {
	*u2f.AuthenticateResponse
	NewCounter uint32
}

func RegisterHardwareToken(caPoolOverride *x509.CertPool) (*u2fhelper.Registration, error) {
	challenge, err := u2fhelper.NewChallenge(u2fFaucetAndID, []string{u2fFaucetAndID})
	if err != nil {
		return nil, err
	}

	// Format used by github.com/tstranex/u2f
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge.Challenge)
	registrationData, err := doU2FRegistration(encodedChallenge)
	if err != nil {
		return nil, err
	}

	convertedResponse := u2fhelper.RegisterResponse{
		Version:          registrationData.Version,
		RegistrationData: registrationData.RegistrationData,
		ClientData:       registrationData.ClientData,
	}

	// Default config with default CA pool, with override configurable via hardcoded option
	// (see oidc/oidc.go for details.)
	cfg := u2fhelper.Config{}
	if caPoolOverride != nil && len(caPoolOverride.Subjects()) > 0 {
		cfg.RootAttestationCertPool = caPoolOverride
	}

	return u2fhelper.Register(convertedResponse, *challenge, &cfg)
}

func doU2FRegistration(encodedChallenge string) (*U2FRegistrationData, error) {
	request := &u2f.RegisterRequest{
		Challenge: encodedChallenge,
		AppId:     u2fFaucetAndID,
		Facet:     u2fFaucetAndID,
	}

	devices := u2f.Devices()
	if len(devices) == 0 {
		return nil, fmt.Errorf("no supported FIDO U2F devices detected to secure privileged credentials, cannot proceed")
	}

	var openDevices []u2f.Device
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, devices[i])
			defer func(i int) {
				devices[i].Close()
			}(i)
		}
	}
	if len(openDevices) == 0 {
		return nil, fmt.Errorf("no FIDO U2F devices connected is available to use, cannot proceed")
	}

	fmt.Println("Press button on the FIDO U2F device used to secure privileged credentials, or Ctrl+C to cancel...")
	interval := time.NewTicker(pollInterval)
	waitingForUserPresenceErr := u2f.TestOfUserPresenceRequiredError{}
	for {
		select {
		case <-interval.C:
			for _, device := range openDevices {
				response, err := device.Register(request)
				if err != nil {
					if err.Error() == waitingForUserPresenceErr.Error() {
						continue
					}

					log.Printf("Got error from FIDO U2F device pressed: %+v", err)
				} else {
					version, err := device.Version()
					if err != nil {
						return nil, fmt.Errorf("error detecting version for device %v", device)
					}

					return &U2FRegistrationData{
						response,
						version,
					}, nil
				}
			}
		}
	}
}

func AuthenticateHardwareToken(registration *u2fhelper.Registration) (*U2FAuthenticationData, error) {
	challenge, err := u2fhelper.NewChallenge(u2fFaucetAndID, []string{u2fFaucetAndID})
	if err != nil {
		return nil, err
	}

	// Format used by github.com/tstranex/u2f
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge.Challenge)
	encodedKeyhandle := base64.RawURLEncoding.EncodeToString(registration.KeyHandle)

	request := &u2f.AuthenticateRequest{
		Challenge: encodedChallenge,
		AppId:     u2fFaucetAndID,
		Facet:     u2fFaucetAndID,
		KeyHandle: encodedKeyhandle,
	}

	devices := u2f.Devices()
	if len(devices) == 0 {
		return nil, fmt.Errorf("no supported FIDO U2F devices detected to secure privileged credentials, cannot proceed")
	}

	var openDevices []u2f.Device
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, devices[i])
			defer func(i int) {
				devices[i].Close()
			}(i)
		}
	}
	if len(openDevices) == 0 {
		return nil, fmt.Errorf("no FIDO U2F devices connected is available to use, cannot proceed")
	}

	fmt.Println("Press button on the FIDO U2F device used to secure privileged credentials, or Ctrl+C to cancel...")
	interval := time.NewTicker(pollInterval)
	waitingForUserPresenceErr := u2f.TestOfUserPresenceRequiredError{}
	for {
		select {
		case <-interval.C:
			for _, device := range openDevices {
				response, err := device.Authenticate(request)
				if err != nil {
					if err.Error() == waitingForUserPresenceErr.Error() {
						continue
					}

					log.Printf("Got error from FIDO U2F device pressed: %+v", err)
				} else {
					// github.com/marshallbrekka/go-u2fhost does not seem to check the signature
					// or validate it against a CA, so we have to bring github.com/tstranex/u2f
					// again...
					newCounter, err := registration.Authenticate(u2fhelper.SignResponse{
						KeyHandle:     encodedKeyhandle,
						SignatureData: response.SignatureData,
						ClientData:    response.ClientData,
					}, *challenge, uint32(0))
					if err != nil {
						return nil, fmt.Errorf("error verifying authentication signature: %+v", err)
					}

					resp := &U2FAuthenticationData{
						response,
						newCounter,
					}

					return resp, err
				}
			}
		}
	}
}
