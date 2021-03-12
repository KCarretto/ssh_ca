package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// PrivateKeyFilePath is where the CA private key used for signing certificates is stored.
const PrivateKeyFilePath = "ca.pem"

// Service for issuing SSH certificates.
type Service struct {
	Key *ecdsa.PrivateKey
}

// HTTP handler for the service.
func (svc *Service) HTTP() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/ca.pub", svc.HandleCAPublicKey)
	router.HandleFunc("/request_cert", svc.HandleCertRequest)
	return router
}

// HandleCAPublicKey returns the Certificate Authorities current public key.
func (svc *Service) HandleCAPublicKey(w http.ResponseWriter, r *http.Request) {
	caPub, err := ssh.NewPublicKey(&svc.Key.PublicKey)
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to parse SSH Certificate Authority public key: %s", err.Error()),
			http.StatusInternalServerError,
		)
		return
	}

	w.Write(ssh.MarshalAuthorizedKey(caPub))
}

// HandleCertRequest creates and signs an SSH certificate for the provided user & public key.
func (svc *Service) HandleCertRequest(w http.ResponseWriter, r *http.Request) {
	// Get user Query Param
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(
			w,
			"must provide non-empty value for 'user' when requesting SSH certificate",
			http.StatusBadRequest,
		)
		return
	}

	// Get pubkey Query Param
	b64PubKey := r.URL.Query().Get("b64pubkey")
	if b64PubKey == "" {
		http.Error(
			w,
			"must provide non-empty base 64 encoded value for 'b64pubkey' when requesting SSH certificate",
			http.StatusBadRequest,
		)
		return
	}
	pubKey, err := base64.StdEncoding.DecodeString(b64PubKey)
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to base64 decode provided value for 'b64pubkey': %s", err.Error()),
			http.StatusBadRequest,
		)
		return
	}

	// Create a signer using the CA private key
	signer, err := ssh.NewSignerFromKey(svc.Key)
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to parse SSH Certificate Authority private key: %s", err.Error()),
			http.StatusInternalServerError,
		)
		return
	}

	// Parse the provided public key
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(pubKey)
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf(
				"failed to parse provided SSH public key (must be ECDSA P256): %s",
				err.Error(),
			),
			http.StatusBadRequest,
		)
		return
	}

	// Create a certificate based on the provided information
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshPub,
		KeyId:           user,
		Serial:          1,
		ValidBefore:     uint64(time.Now().Add(time.Hour * 72).Unix()),
		ValidAfter:      uint64(time.Now().Unix()),
		ValidPrincipals: []string{user},
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
		http.Error(
			w,
			fmt.Sprintf(
				"failed to sign user SSH certificate: %s",
				err.Error(),
			),
			http.StatusInternalServerError,
		)
		return
	}

	w.Write(ssh.MarshalAuthorizedKey(cert))
}

func (svc *Service) loadKey() error {
	if !fileExists(PrivateKeyFilePath) {
		caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA P256 private key: %w", err)
		}

		caPrivBytes, err := x509.MarshalECPrivateKey(caPriv)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA P256 private key to SEC1 format: %w", err)
		}

		caPrivPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: caPrivBytes,
		})

		if err := ioutil.WriteFile(PrivateKeyFilePath, caPrivPEM, 0644); err != nil {
			return fmt.Errorf("failed to write ECDSA P256 private key to file %q: %w", PrivateKeyFilePath, err)
		}
		svc.Key = caPriv
		return nil
	}

	caPrivBytes, err := ioutil.ReadFile(PrivateKeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read ECDSA P256 private key file %q: %w", PrivateKeyFilePath, err)
	}

	b, _ := pem.Decode(caPrivBytes)
	if b == nil {
		return fmt.Errorf("failed to PEM decode ECDSA P256 private key file %q", PrivateKeyFilePath)
	}

	caPriv, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSA P256 private key from file %q: %w", PrivateKeyFilePath, err)
	}

	svc.Key = caPriv
	return nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func runApp() {
	svc := &Service{}
	if err := svc.loadKey(); err != nil {
		panic(err)
	}

	fmt.Printf("SSH Certificate Authority listening on :8080\n")
	if err := http.ListenAndServe(":8080", svc.HTTP()); err != nil {
		panic(err)
	}
}
