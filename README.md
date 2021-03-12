# SSH Certificate Authority
The goal of this service is to supply a lightweight implementation of a Certificate Authority (CA) for SSH Certificates. This Windows service uses a CA private key which is used to sign given public keys for users. Then any SSH Server with the proper configuration will accept the newly issued SSH certificates for authentication. More information on the implementation of the SSH Certificate Authority & SSH server configuration requirements can be found below.

## API
The service hosts 5 HTTP endpoints on port `8080` to allow interaction with it. Some endpoints of the API are secured behind a level of basic authentication(single password).

### / - GET
The base endpoint displays general information about the service as well as allowing for a UI for rotating the CA private / public keypair, requesting new SSH certificates, and changing the service password.

### /ca.pub - GET
This endpoint is for retrieving the public key associated with the root key for the service. This is a crucial file necessary to keep synced on all SSH Servers so that User Certificates properly validate. This endpoint is unauthenticated, so systems administrators may `curl` this endpoint in order to retrieve an updated CA public key.

### /request_cert?b64pubkey=<b64_pubkey>&user=<ssh_username> - GET {AUTHENTICATED}
This endpoint is used for signing a specific SSH certificate for a specific user. The first query parameter is a base64 encoding of the content of an ECDSA P256 ssh public key file. As an example, if an ssh public key is 

```ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDW+M8gDB+ZX3/PPyGGiNgDItvw3O42vnw43th8zhhoKtWfqzqxy8OrjrcG4NWx0WbD/b1D92PzreiMaSuaxU24= user@localhost.localdomain```

then this value should be 

```ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4eThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo=```.

The second query param should match the username of the user you wish the certificate being minted to be valid for. As and example, `user`. The response will be returned as the raw text for the newly minted SSH certificate.


### /rotate - POST {AUTHENTICATED}
This endpoint is responsible for rotating the SSH CA's public and private keys in the event of them being compromised/expired. After this is done, be sure to quickly update the corresponding SSH Servers with the new `ca.pub` so that new SSH certificates don't fail authentication. After the keys are rotated the new private key is flushed to disk in the service's directory. 

### /change_password - POST {AUTHENTICATED}
This endpoint is used for changing the password of the service’s Web API. This service is strictly single user and as such only has one user/credential pair. The user is statically `admin`, the password will default to `changeme`. When this endpoint is hit the new password will also be flushed to disk in the service's directory.


## SSH-CA Service Configuration
There are basic configuration files that help the SSH CA remain persistent on service/system restart. These files are located in the service's directory (`C:\Program Files (x86)\SSH Certificate Authority`). There are two main files: `ca.pem`(private key) and `admin_password`(service password). In the event the private key file is missing and the service is restarted, a new public/private key pair will be generated and flushed to disk. If the service password file is missing and the service is restarted, the service will start using the default password.

## SSH Server Integration
SSH Servers will need to have the `TrustedUserCAKeys` option set in their configuration file in order for the user certificates to be used as an authentication mechanism. This option should point to a local copy of the SSH CA's public key (reachable at the `/ca.pub` endpoint).

## Using the Certificates
If the service is deployed correctly, then a new form of authentication is available for use when connecting over SSH. Similar to how regular SSH public/private keys operate, you will need to generate a key pair on a client you will wish to connect with. Once you have a key pair you can make a request to the SSH Certificate Authority API at the `request_cert` endpoint (be sure to choose which user you wish to mint a certificate for carefully!). Then simply place the new user cert with the `-cert.pub` suffix into the `.ssh` directory (or wherever your private keys are stored). For example, if the private key file was named `id_ecdsa` then the SSH certificate would be named `id_ecdsa-cert.pub`. After that you should be able to SSH directly onto the SSH Server (only for the user you requested the certificate for).

## Keys
This project uses `ecdsa-sha2-nistp256` keys that can be generated via `ssh-keygen -t ecdsa -b 256`. Any other types of keys are unsupported with the current version of this service.

