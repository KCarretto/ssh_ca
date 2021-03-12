# SSH Certificate Authority
The goal of this service is to supply a lightweight implementation of a Certificate Authority for SSH Keys. This Windows service holds one root key in memory which is used to sign given public keys for users. Then any SSH Server with the proper configuration will be able to use the newly minted User Certificates for authentication.

## API
The service hosts 5 HTTP endpoints  on port `8080` to allow interaction with it. Some endpoints of the API are secured behind a level of basic authenitcation(single password).

### / - GET
The base endpoint displays general information about the service as well as allowing for a UI for rotating the root key, getting a new user certificate, changing the service password.

### /ca.pub - GET
This endpoint is for retrieving the public key associated with the root key for the service. This is a crucial file necessary to keep synced on all SSH Servers so that User Certificates properly validate.

### /request_cert?b64pubkey=<b64_pubkey>&user=<ssh_username> - GET {AUTHENTICATED}
This endpoint is used for signing a specific ssh public key for use for a specific user. The first query parameter is a base64 encoding of the content of a regular ssh public key file. As an example, if an ssh public key is 

```ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDW+M8gDB+ZX3/PPyGGiNgDItvw3O42vnw43th8zhhoKtWfqzqxy8OrjrcG4NWx0WbD/b1D92PzreiMaSuaxU24= user@localhost.localdomain```

then this value should be 

```ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4eThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo=```.

The second query param should match the username of the user you wish the certificate being minted to be valid for. As and example, `user`. The response will be returned as the raw text for the newly minted user certificate.


### /rotate - POST {AUTHENTICATED}
This endpoint is responsible for rotating the SSH CA's root keys in the event of them being compromised/expired. After this is done, be sure to quickly update the corresponding SSH Servers with the new `ca.pub` so that any newly minted user certificated don't fail to validate and anyone with the old key cannot mint new valide certificated. After the keys are rotated the private is flushed to disk in the service's directory.

### /change_password - POST {AUTHENTICATED}
This endpoint is used for changing the password of the Web API of the service. This service is strictly single user and as such only has one user/credential pair. The user is statically `admin`, the password will default to `changeme`. When this endpoint is hit the new password will also be flushed to disk in the service's directory.


## SSH-CA Service Configuration
There are basic configuration files that help the SSH CA remain persistent on service/system restart. These files are located in the service's directory (`C:\Program Files (x86)\SSH Certificate Authority`). There are two main files: `ca.pem`(private key) and `admin_password`(service password). In the event the private key file is missing and the service is restarted, a new public/private key pair will be generated and flushed to disk. If the service password file is missing and the service is restarted, the password will go back to the default.

## SSH Server Integration
SSH Servers will need to have the `TrustedUserCAKeys` option set in their configuration file in order for the user certificates to be used as an authentication mechanism. This option should point to a local copy of the SSH CA's public key (reachable at the `/ca.pub` endpoint).

## Using the Certificates
If the service is correctly setup then a new form of authenitcation is available for use when connecting over SSH. Similar to how regular ssh public/private keys work you will need to generate a key pair on a client you will wish to connect with. Once you have a key pair you can make a request to the SSH CA API at the `request_cert` endpoint (be sure to choose which user you wish to mint a certificate for carefully!). Then simply place the new user cert with the `-cert.pub` suffix into the `.ssh` directory (or wherever your private keys are stored). For example, if the private key file was named `id_ecdsa` then the user certificate would be named `id_ecdsa-cert.pub`. After that you should be able to ssh directly onto the SSH Server (only for the user you requested to make the certificate for).

## Keys
This project uses `ecdsa-sha2-nistp256` keys that can be generated via `ssh-keygen -t ecdsa -b 256`. Any other types of keys are unsupported with the current version of this service. 
