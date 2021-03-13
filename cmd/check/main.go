package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"
)

func caCheck(user, password, host string) error {
	// 1. Generate Keypair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] failed to generate ECDSA private key: %w", err)
	}

	// 2. Marshal Public Key
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] failed to marshal SSH public key: %w", err)
	}
	b64pubkey := base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pub))

	// 3. Prepare HTTP Request
	params := &url.Values{}
	params.Set("user", user)
	params.Set("b64pubkey", b64pubkey)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(
		"%s/request_cert?%s",
		host,
		params.Encode(),
	), nil)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] Failed to initialize HTTP request struct: %w", err)
	}
	req.SetBasicAuth("admin", password)

	// 4. Request Certificate from SSH Certificate Authority
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request SSH certificate from SSH Certificate Authority: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSH Certificate Authority returned non 200 status code: %d", resp.StatusCode)
	}

	// 5. Parse SSH Certificate from CA Response
	rawCert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to get SSH certificate from HTTP response body: %w", err)
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawCert))
	if err != nil {
		return fmt.Errorf("failed to parse SSH client certificate: %w", err)
	}
	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("received public key is not a valid ssh certificate")
	}

	// 6. Request CA Public Key
	resp, err = http.Get(host + "/ca.pub")
	if err != nil {
		return fmt.Errorf("failed to retrieve public key from SSH Certificate Authority: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSH Certificate Authority returned non-200 HTTP status code when requesting CA Public Key: %d", resp.StatusCode)
	}

	// 7. Parse CA Public Key from CA Response
	caPub, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse SSH Certificate Authority Public Key from HTTP response body: %w", err)
	}

	certSignerPubkey := string(ssh.MarshalAuthorizedKey(sshCert.SignatureKey))

	if string(caPub) != certSignerPubkey {
		return fmt.Errorf("signature mismatch: SSH Certificate was signed by a Public Key that does not belong to the SSH Certificate Authority")
	}

	return nil
}

func sshCheck(cmd, user, password, host, caHost string) error {
	// 1. Generate Keypair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] failed to generate ECDSA private key: %w", err)
	}

	// 2. Marshal Public Key
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] failed to marshal SSH public key: %w", err)
	}
	b64pubkey := base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pub))

	// 3. Create Signer using Private Key
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] failed to create signer from ssh private key: %w", err)
	}

	// 4. Prepare HTTP Request
	params := &url.Values{}
	params.Set("user", user)
	params.Set("b64pubkey", b64pubkey)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(
		"%s/request_cert?%s",
		caHost,
		params.Encode(),
	), nil)
	if err != nil {
		return fmt.Errorf("[CONTACT BLACK TEAM] Failed to initialize HTTP request struct: %w", err)
	}
	req.SetBasicAuth("admin", password)

	// 5. Request Certificate from SSH Certificate Authority
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request SSH certificate from SSH Certificate Authority: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSH Certificate Authority returned non 200 status code: %d", resp.StatusCode)
	}

	// 6. Parse SSH Certificate from CA Response
	rawCert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to get SSH certificate from HTTP response body: %w", err)
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawCert))
	if err != nil {
		return fmt.Errorf("failed to parse SSH client certificate: %w", err)
	}
	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("received public key is not a valid ssh certificate")
	}

	// 7. Combine SSH Certificate & PrivateKey into Signer auth method
	sshCertSigner, err := ssh.NewCertSigner(sshCert, signer)
	if err != nil {
		return fmt.Errorf("failed to use certificate as an auth method, perhaps the private key is a mismatch: %w", err)
	}

	// 8. Configure SSH Client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(sshCertSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 9. Connect to host via SSH (Certificate Auth)
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return fmt.Errorf("failed to connect to ssh using certificate: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to establish SSH session with remote host: %w", err)
	}

	if _, err := session.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("failed to execute command %q via SSH session: %w", cmd, err)
	}
	return nil
}

func main() {
	fmt.Printf("[+] Starting SSH Certificate Authority Check\n")
	if err := caCheck(
		"user",
		"changeme",
		"http://35.188.122.132:8080",
	); err != nil {
		panic(err)
	}
	fmt.Printf("[+] SSH Certificate Authority Check Successful\n")

	fmt.Printf("[+] Starting SSH Check\n")
	if err := sshCheck(
		"touch /tmp/hi_nick",
		"user",
		"changeme",
		"192.168.1.231:22",
		"http://35.188.122.132:8080",
	); err != nil {
		panic(err)
	}
	fmt.Printf("[+] SSH Check Successful\n")

}
