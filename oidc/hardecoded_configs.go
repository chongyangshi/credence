package oidc

import "crypto/x509"

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

	overrideDeviceAttestationCAPool *x509.CertPool = nil
	// If you want to only trust U2F device attestation CAs from specific
	// hardware token device vendors, this should be configured explicitly
	// in code, before compiling and signing the binary for distribution
	// to your fleet machines. For example to trust YubiKeys only:
	/*
		const yubicoRootCert = `-----BEGIN CERTIFICATE-----
		MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
		dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
		MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
		IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
		AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
		5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
		8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
		nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
		9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
		LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
		hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
		BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
		MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
		hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
		LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
		sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
		U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
		-----END CERTIFICATE-----
		`

		func init() {
			overrideDeviceAttestationCAPool = x509.NewCertPool()
			if !overrideDeviceAttestationCAPool.AppendCertsFromPEM([]byte(yubicoRootCert)) {
				log.Fatal("u2f: Error loading root cert pool.")
			}
		}
	*/
)
