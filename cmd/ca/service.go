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
	"math"
	"math/big"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Service for issuing SSH certificates.
type Service struct {
	Key      *ecdsa.PrivateKey
	Password string
	Log      func(string)
	Warn     func(string)
}

// HTTP handler for the service.
func (svc *Service) HTTP() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/", svc.HandleIndex)
	router.HandleFunc("/about", svc.HandleAbout)
	router.HandleFunc("/ca.pub", svc.HandleCAPublicKey)
	router.HandleFunc("/request_cert", svc.requireAuth(svc.HandleCertRequest))
	router.HandleFunc("/change_password", svc.requireAuth(svc.HandlePasswordChange))
	router.HandleFunc("/rotate", svc.requireAuth(svc.HandleRotateCAKeys))
	return router
}

// HandleIndex serves the index HTML page for the site.
func (svc *Service) HandleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(IndexHTML))
}

// HandleAbout serves the about HTML page for the site.
func (svc *Service) HandleAbout(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(AboutHTML))
}

// HandlePasswordChange enables users to post a form in order to change the admin credential.
func (svc *Service) HandlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"must be a POST request",
			http.StatusMethodNotAllowed,
		)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to parse request form: %s", err.Error()),
			http.StatusBadRequest,
		)
		return
	}
	password := r.Form.Get("password")
	if password == "" {
		http.Error(
			w,
			"Cannot provide empty value for 'password'",
			http.StatusBadRequest,
		)
		return
	}
	if err := svc.savePassword(password); err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to save password: %s", err.Error()),
			http.StatusInternalServerError,
		)
		return
	}

	svc.log(fmt.Sprintf("Service admin password changed by %s", r.RemoteAddr))
	w.Write([]byte("Password changed successfully\n"))
}

// HandleRotateCAKeys changes the keypair used by the CA to sign SSH certificates.
// The new CA Public Key MUST be deployed to SSH servers for authentication to succeed.
func (svc *Service) HandleRotateCAKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"must be a POST request",
			http.StatusMethodNotAllowed,
		)
		return
	}

	if fileExists(PrivateKeyFilePath) {
		if err := os.Remove(PrivateKeyFilePath); err != nil {
			http.Error(
				w,
				fmt.Sprintf(
					"failed to remove CA private key file %q: %s",
					PrivateKeyFilePath,
					err.Error(),
				),
				http.StatusInternalServerError,
			)
			return
		}
	}
	if err := svc.loadKey(); err != nil {
		http.Error(
			w,
			fmt.Sprintf("failed to generate new CA private key: %s", err.Error()),
			http.StatusInternalServerError,
		)
		return
	}

	svc.log(fmt.Sprintf("CA Private & Public keys rotated by %s", r.RemoteAddr))
	w.Write([]byte("CA Private & Public Keys successfully rotated\n"))
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
				"failed to parse provided SSH public key (must be ECDSA P256): %s, Ensure you've provided a valid PUBLIC KEY",
				err.Error(),
			),
			http.StatusBadRequest,
		)
		return
	}

	var serial uint64 = 1
	bigSerial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err == nil && bigSerial != nil {
		serial = bigSerial.Uint64()
		if serial < uint64(1) {
			serial = uint64(1)
		}
	}

	// Create a certificate based on the provided information
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshPub,
		KeyId:           fmt.Sprintf("%X", serial),
		Serial:          serial,
		ValidBefore:     uint64(time.Now().Add(time.Hour * 24 * 14).Unix()),
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

	sshCert := ssh.MarshalAuthorizedKey(cert)
	svc.log(fmt.Sprintf("Issued new certificate to %s (from %s): %s", user, r.RemoteAddr, string(sshCert)))
	w.Write(sshCert)
}

func (svc *Service) savePassword(password string) error {
	if err := ioutil.WriteFile(PasswordFilePath, []byte(password), 0644); err != nil {
		return fmt.Errorf("failed to write password to file %q: %w", PasswordFilePath, err)
	}
	svc.Password = password
	return nil
}

func (svc *Service) loadPassword() error {
	if !fileExists(PasswordFilePath) {
		svc.Password = DefaultPassword
		return svc.savePassword(DefaultPassword)
	}
	password, err := ioutil.ReadFile(PasswordFilePath)
	if err != nil {
		svc.Password = DefaultPassword
		return fmt.Errorf("failed to read password file, utilizing default credentials: %w", err)
	}
	if string(password) == "" {
		svc.Password = DefaultPassword
		return fmt.Errorf("password file contains empty password, utilizing default credentials")
	}

	svc.Password = string(password)
	return nil
}

func (svc *Service) saveKey(caPriv *ecdsa.PrivateKey) error {
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

	return nil
}

func (svc *Service) loadKey() error {
	if !fileExists(PrivateKeyFilePath) {
		caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA P256 private key: %w", err)
		}

		if err := svc.saveKey(caPriv); err != nil {
			return err
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

func (svc *Service) requireAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != DefaultUser || pass != svc.Password {
			svc.warn(fmt.Sprintf(
				"Request to %s failed, invalid authentication credentials from %s",
				r.RequestURI,
				r.RemoteAddr,
			))
			w.Header().Add("WWW-Authenticate", "Basic")
			http.Error(w, "Unauthorized.", 401)
			return
		}
		fn(w, r)
	}
}

func (svc *Service) log(msg string) {
	if svc.Log != nil {
		svc.Log(msg)
	} else {
		fmt.Println(msg)
	}
}

func (svc *Service) warn(msg string) {
	if svc.Warn != nil {
		svc.Warn(msg)
	} else {
		fmt.Println(msg)
	}
}

func runApp() {
	svc := &Service{}
	if err := svc.loadKey(); err != nil {
		panic(err)
	}
	if err := svc.loadPassword(); err != nil {
		fmt.Printf("[ERROR] Failed to load password: %v\n", err)
	}

	fmt.Printf("SSH Certificate Authority listening on :8080\n")
	if err := http.ListenAndServe(":8080", svc.HTTP()); err != nil {
		panic(err)
	}
}
