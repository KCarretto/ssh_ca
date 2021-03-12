package main

// PrivateKeyFilePath is where the CA private key used for signing certificates is stored.
// PasswordFilePath is where the admin password for the application is stored.
// DefaultUser name for the CA admin
// DefaultPassword for the CA admin
const (
	PrivateKeyFilePath = `C:\Program Files (x86)\SSH Certificate Authority\ca.pem`
	PasswordFilePath   = `C:\Program Files (x86)\SSH Certificate Authority\admin_password`
	DefaultUser        = "admin"
	DefaultPassword    = "changeme"
)

const (
	svcName = "SSH Certificate Authority"
	svcDesc = "(SCORED SERVICE) Issues SSH Certificates that are used to authenticate to Linux machines. The scoring engine requests SSH certificates via HTTP (port 8080) from this service, and then attempts to SSH to Linux machines in the environment using these certificates."
)

// LogEventServiceSignal event code for when the service receives a control signal
// LogEventGeneral event code for general operational information
// LogEventStateChange event code for when the application state has been changed (e.g. cert issued)
// LogEventHTTPRequest event code for when the application receives HTTP requests
const (
	LogEventServiceSignal = 1
	LogEventGeneral       = 2
	LogEventStateChange   = 22
	LogEventHTTPRequest   = 80
)
