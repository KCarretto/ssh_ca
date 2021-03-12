package main

const AboutHTML = `
<!DOCTYPE html>
<html>
<body>

<h1 id="ssh-certificate-authority">SSH Certificate Authority</h1>
<p>The goal of this service is to supply a lightweight implementation of a Certificate Authority (CA) for SSH Certificates. This Windows service uses a CA private key which is used to sign given public keys for users. Then any SSH Server with the proper configuration will accept the newly issued SSH certificates for authentication. More information on the implementation of the SSH Certificate Authority &amp; SSH server configuration requirements can be found below.</p>
<h2 id="api">API</h2>
<p>The service hosts 5 HTTP endpoints on port <code>8080</code> to allow interaction with it. Some endpoints of the API are secured behind a level of basic authentication(single password).</p>
<h3 id="-get">/ - GET</h3>
<p>The base endpoint displays general information about the service as well as allowing for a UI for rotating the CA private / public keypair, requesting new SSH certificates, and changing the service password.</p>
<h3 id="-ca-pub-get">/ca.pub - GET</h3>
<p>This endpoint is for retrieving the public key associated with the root key for the service. This is a crucial file necessary to keep synced on all SSH Servers so that User Certificates properly validate. This endpoint is unauthenticated, so systems administrators may <code>curl</code> this endpoint in order to retrieve an updated CA public key.</p>
<h3 id="-request_cert-b64pubkey-b64_pubkey-user-ssh_username-get-authenticated-">/request_cert?b64pubkey=abase64publickeyhere&amp;user=root - GET {AUTHENTICATED}</h3>
<p>This endpoint is used for signing a specific SSH certificate for a specific user. The first query parameter is a base64 encoding of the content of an ECDSA P256 ssh public key file. As an example, if an ssh public key is </p>
<p><code>ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDW+M8gDB+ZX3/PPyGGiNgDItvw3O42vnw43th8zhhoKtWfqzqxy8OrjrcG4NWx0WbD/b1D92PzreiMaSuaxU24= user@localhost.localdomain</code></p>
<p>then this value should be </p>
<p><code>ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4eThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo=</code>.</p>
<p>The second query param should match the username of the user you wish the certificate being minted to be valid for. As and example, <code>user</code>. The response will be returned as the raw text for the newly minted SSH certificate.</p>
<h3 id="-rotate-post-authenticated-">/rotate - POST {AUTHENTICATED}</h3>
<p>This endpoint is responsible for rotating the SSH CA&#39;s public and private keys in the event of them being compromised/expired. After this is done, be sure to quickly update the corresponding SSH Servers with the new <code>ca.pub</code> so that new SSH certificates don&#39;t fail authentication. After the keys are rotated the new private key is flushed to disk in the service&#39;s directory. </p>
<h3 id="-change_password-post-authenticated-">/change_password - POST {AUTHENTICATED}</h3>
<p>This endpoint is used for changing the password of the service’s Web API. This service is strictly single user and as such only has one user/credential pair. The user is statically <code>admin</code>, the password will default to <code>changeme</code>. When this endpoint is hit the new password will also be flushed to disk in the service&#39;s directory.</p>
<h2 id="ssh-ca-service-configuration">SSH-CA Service Configuration</h2>
<p>There are basic configuration files that help the SSH CA remain persistent on service/system restart. These files are located in the service&#39;s directory (<code>C:\Program Files (x86)\SSH Certificate Authority</code>). There are two main files: <code>ca.pem</code>(private key) and <code>admin_password</code>(service password). In the event the private key file is missing and the service is restarted, a new public/private key pair will be generated and flushed to disk. If the service password file is missing and the service is restarted, the service will start using the default password.</p>
<h2 id="ssh-server-integration">SSH Server Integration</h2>
<p>SSH Servers will need to have the <a href="https://man.openbsd.org/sshd_config#TrustedUserCAKeys" target="_blank">TrustedUserCAKeys</a> option set in their configuration file in order for the user certificates to be used as an authentication mechanism. This option should point to a local copy of the SSH CA&#39;s public key (reachable at the <code>/ca.pub</code> endpoint).</p>
<h2 id="using-the-certificates">Using the Certificates</h2>
<p>If the service is deployed correctly, then a new form of authentication is available for use when connecting over SSH. Similar to how regular SSH public/private keys operate, you will need to generate a key pair on a client you will wish to connect with. Once you have a key pair you can make a request to the SSH Certificate Authority API at the <code>request_cert</code> endpoint (be sure to choose which user you wish to mint a certificate for carefully!). Then simply place the new user cert with the <code>-cert.pub</code> suffix into the <code>.ssh</code> directory (or wherever your private keys are stored). For example, if the private key file was named <code>id_ecdsa</code> then the SSH certificate would be named <code>id_ecdsa-cert.pub</code>. After that you should be able to SSH directly onto the SSH Server (only for the user you requested the certificate for).</p>
<h2 id="keys">Keys</h2>
<p>This project uses <code>ecdsa-sha2-nistp256</code> keys that can be generated via <code>ssh-keygen -t ecdsa -b 256</code>. Any other types of keys are unsupported with the current version of this service.</p>

</body>
</html>
`
