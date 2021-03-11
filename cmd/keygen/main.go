package main

// /*
// 	Option 1. Build CA Service
// 		* How to start at run?
// 		* Service vs Exe?
// 		* How to retrieve CA key

// 	Option 2. Have them paste the private key
// 		* How will they deploy a new ssh public key?
// */

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

type Issuer struct {
	Key *ecdsa.PrivateKey
}

// IssueCertificate and pray it works.
func (issuer *Issuer) IssueCertificate(user, pubKey string) string {
	signer, err := ssh.NewSignerFromKey(issuer.Key)
	if err != nil {
		panic(fmt.Errorf("failed to parse CA private key: %w", err))
	}

	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		panic(fmt.Errorf("failed to parse provided public key: %w", err))
	}

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshPub,
		KeyId:           "user",
		Serial:          1,
		ValidBefore:     uint64(time.Now().Add(time.Hour * 72).Unix()),
		ValidAfter:      uint64(time.Now().Unix()),
		ValidPrincipals: []string{"user"},
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		panic(err)
	}

	return string(ssh.MarshalAuthorizedKey(cert))
}

func main() {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	caPub, err := ssh.NewPublicKey(&caPriv.PublicKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssh.MarshalAuthorizedKey(caPub))

	caPrivBytes, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n\n", pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caPrivBytes,
	}))

	fmt.Printf("\n\n================================\n\n")

	// ca := &Issuer{
	// 	Key: caPriv,
	// }

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	pubBytes := ssh.MarshalAuthorizedKey(pub)

	fmt.Printf("%s\n\n", pubBytes)
	fmt.Printf("%s\n\n", pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}))

	////////////////////////////////////////

	// cert := ca.IssueCertificate("user", string(pubBytes))
	// fmt.Printf("%s\n", cert)

	///////////////////////////////////////
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		panic(fmt.Errorf("failed to parse CA private key: %w", err))
	}

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pub,
		KeyId:           "user",
		Serial:          1,
		ValidBefore:     uint64(time.Now().Add(time.Hour * 72).Unix()),
		ValidAfter:      uint64(time.Now().Unix()),
		ValidPrincipals: []string{"user"},
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssh.MarshalAuthorizedKey(cert))

}

// signer, err := ssh.NewSignerFromKey(sshCAPrivKey)
// if err != nil {
// 	panic(err)
// }

// permissions := ssh.Permissions{
// 	CriticalOptions: map[string]string{},
// 	Extensions:      map[string]string{"permit-agent-forwarding": ""},
// }
// cert := &ssh.Certificate{
// 	ValidPrincipals: []string{"user"},
// 	CertType:        ssh.UserCert, Permissions: permissions, Key: sshPubKey,
// }

// if err := cert.SignCert(rand.Reader, signer); err != nil {
// 	panic(err)
// }
