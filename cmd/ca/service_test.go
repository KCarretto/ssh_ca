package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCAPubKey  = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM1GWHAUxdHZeNl6fSTTD8ROFgGVF2og4BBVuK77UkCD1UKWOlQ/ItT8Jf9kDLkM+yH+OFmieaYt06mokXOwnFs=\n"
	testCAPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJd5UXND7gGudgUKNIgkp694y2GSc6fSluUALVSaiJYVoAoGCCqGSM49
AwEHoUQDQgAEzUZYcBTF0dl42Xp9JNMPxE4WAZUXaiDgEFW4rvtSQIPVQpY6VD8i
1Pwl/2QMuQz7If44WaJ5pi3TqaiRc7CcWw==
-----END EC PRIVATE KEY-----
`
	testUserPubKey  = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIryjrjTIk+zhusHJLADCvzgpo890/MrzV5DeVjxtfwrWw8kH6AkYnsG5a9as+AfDF3JgVyOmKOZXwi8NCMvvaQ=\n"
	testUserPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDeaZaVh6WR38imgwMbM3r60mj0LTbzaJQfRKF0oJSDMoAoGCCqGSM49
AwEHoUQDQgAEivKOuNMiT7OG6wcksAMK/OCmjz3T8yvNXkN5WPG1/CtbDyQfoCRi
ewblr1qz4B8MXcmBXI6Yo5lfCLw0Iy+9pA==
-----END EC PRIVATE KEY-----
`
)

// TestHandleCAPublicKey ensures the proper public key is returned from the CA.
func TestHandleCAPublicKey(t *testing.T) {
	req, err := http.NewRequest("GET", "/ca.pub", nil)
	require.NoError(t, err)

	b, _ := pem.Decode([]byte(testCAPrivKey))

	caPriv, err := x509.ParseECPrivateKey(b.Bytes)
	require.NoError(t, err)

	svc := &Service{
		Key: caPriv,
	}

	rr := httptest.NewRecorder()
	svc.HTTP().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, testCAPubKey, rr.Body.String(), "CA Public Key Mismatch")
}

// TestHandleCertRequest ensures a valid certificate is returned from the CA.
func TestHandleCertRequest(t *testing.T) {
	params := url.Values{}
	params.Set("user", "user")
	params.Set("b64pubkey", base64.StdEncoding.EncodeToString([]byte(testUserPubKey)))

	endpoint := "/request_cert?" + params.Encode()
	// fmt.Printf("HTTP Request: %q", endpoint)
	req, err := http.NewRequest("GET", endpoint, nil)
	require.NoError(t, err)

	b, _ := pem.Decode([]byte(testCAPrivKey))

	caPriv, err := x509.ParseECPrivateKey(b.Bytes)
	require.NoError(t, err)

	svc := &Service{
		Key: caPriv,
	}

	rr := httptest.NewRecorder()
	svc.HTTP().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	result, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rr.Body.String()))
	require.NoError(t, err)

	cert := result.(*ssh.Certificate)

	require.Len(t, cert.ValidPrincipals, 1)
	assert.Equal(t, cert.ValidPrincipals[0], "user")
	assert.Equal(t, cert.Serial, uint64(1))
	assert.NotNil(t, cert.Signature)
	assert.LessOrEqual(t, cert.ValidAfter, uint64(time.Now().Unix()))
	assert.GreaterOrEqual(t, cert.ValidBefore, uint64(time.Now().Unix()))
}

// TestHandleChangePassword ensures the CA properly changes its password.
func TestHandleChangePassword(t *testing.T) {
	expectedPassword := "changed!"
	params := &url.Values{}
	params.Set("password", expectedPassword)

	req, err := http.NewRequest(http.MethodPost, "/change_password", strings.NewReader(params.Encode()))
	require.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	svc := &Service{}

	svc.loadPassword()
	require.Equal(t, DefaultPassword, svc.Password, "password mismatch")

	rr := httptest.NewRecorder()
	svc.HTTP().ServeHTTP(rr, req)
	defer os.Remove(PasswordFilePath)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, expectedPassword, svc.Password)
}

// TestHandleRotateCAKeys ensures the CA properly rotates its keypair.
func TestHandleRotateCAKeys(t *testing.T) {
	defer os.Remove(PrivateKeyFilePath)

	req, err := http.NewRequest(http.MethodPost, "/rotate", nil)
	require.NoError(t, err)

	b, _ := pem.Decode([]byte(testCAPrivKey))

	caPriv, err := x509.ParseECPrivateKey(b.Bytes)
	require.NoError(t, err)

	svc := &Service{
		Key: caPriv,
	}

	rr := httptest.NewRecorder()
	svc.HTTP().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, svc.Key)

	keyBytes, err := x509.MarshalECPrivateKey(svc.Key)
	require.NoError(t, err)

	require.NotEqual(t,
		testCAPrivKey,
		string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})),
	)
}
