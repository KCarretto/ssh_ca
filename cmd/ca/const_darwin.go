package main

// PrivateKeyFilePath is where the CA private key used for signing certificates is stored.
// PasswordFilePath is where the admin password for the application is stored.
// DefaultUser name for the CA admin
// DefaultPassword for the CA admin
const (
	PrivateKeyFilePath = "ca.pem"
	PasswordFilePath   = "admin_password"
	DefaultUser        = "admin"
	DefaultPassword    = "changeme"
)
