package main

const AboutHTML = `
<!DOCTYPE html>
<html>
<head>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.js" integrity="sha512-dqw6X88iGgZlTsONxZK9ePmJEFrmHwpuMrsUChjAw1mRUhUITE5QU9pkcSox+ynfLhL15Sv2al5A0LVyDCmtUw==" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.css" integrity="sha512-8bHTC73gkZ7rZ7vpqUQThUDhqcNFyYi2xgDgPDHc+GXVGHXq+xPjynxIopALmOPqzo9JZj0k6OqqewdGO3EsrQ==" crossorigin="anonymous" />
</head>
<body style="background-color:#EEEEEE;">

<div class="ui borderless menu">
  <div class="item">
    <h2 class="ui header">
      <i class="key icon"></i>
      <div class="content">
        SSH Certificate Authority
        <div class="sub header">Providing Secure Authentication</div>
      </div>
    </h2>
  </div>

  <div class="item">
    <a class="item" href="/">
      Home
    </a>
  </div>

  <div class="item">
    <a class="item" href="/about">
      Documentation
    </a>
  </div>
</div>

<div class="ui raised segment">
  <p>Welcome to the SSH Certificate Authority (CA)! This HTTP service is responsible for issuing new SSH certificates to clients that wish to connect to our Linux infrastructure. Our CA Public Key (which can be found <a href="/ca.pub">here</a>) is deployed to all Linux machines in our environment. Any SSH certificate signed by this CA will be able to authenticate to Linux hosts in our environment via SSH. More information on the implementation of the SSH Certificate Authority &amp; SSH server configuration requirements can be found below.</p>
</div>


<div class="ui raised segment">
  <h2 class="ui dividing icon header">
	<i class="cloud upload icon"></i>
	<div class="content">
	API
	<div class="sub header">Learn about our HTTP API.</div>
	</div>
  </h2>

  <p>The service hosts 5 HTTP endpoints on port <code>8080</code> to allow interaction with it. Some endpoints of the API are secured behind a level of basic authentication(single password).</p>
	<div class="ui styled fluid accordion">

	  <div class="active title">
		<i class="dropdown icon"></i>
		/ <div class="ui label">GET</div><div class="ui blue label">Unauthenticated</div>
	  </div>
	  <div class="active content">
	    <p>The base endpoint displays general information about the service as well as allowing for a UI for rotating the CA private / public keypair, requesting new SSH certificates, and changing the service password.</p>
	  </div>

	  <div class="title">
		<i class="dropdown icon"></i>
		/ca.pub <div class="ui label">GET</div><div class="ui blue label">Unauthenticated</div>
	  </div>
	  <div class="content">
	    <p>This endpoint is for retrieving the public key associated with the root key for the service. This is a crucial file necessary to keep synced on all SSH Servers so that User Certificates properly validate. This endpoint is unauthenticated, so systems administrators may <code>curl</code> this endpoint in order to retrieve an updated CA public key.</p>
	  </div>

	  <div class="title">
		<i class="dropdown icon"></i>
		/request_cert <div class="ui label">GET</div><div class="ui blue label">Authenticated</div><div class="ui green label">Query Param: b64pubkey</div><div class="ui green label">Query Param: user</div>
	  </div>
	  <div class="content">
		<p>This endpoint is used for signing a specific SSH certificate for a specific user. The first query parameter is a base64 encoding of the content of an ECDSA P256 ssh public key file.
		<br/><br/><br/>As an example, if an ssh public key is:<br/>br/>
		<code>ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDW+M8gDB+ZX3/PPyGGiNgDItvw3O42vnw43th8zhhoKtWfqzqxy8OrjrcG4NWx0WbD/b1D92PzreiMaSuaxU24= user@localhost.localdomain</code>
		<br/><br/>Then this value should be:<br/>
		<code>ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4eThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo=</code>
		<br/><br/>The second query param should match the username of the user you wish the certificate being minted to be valid for. As and example, <code>user</code>. The response will be returned as the raw text for the newly minted SSH certificate.
		</p>
	  </div>

	  <div class="title">
	    <i class="dropdown icon"></i>
	    /rotate <div class="ui label">POST</div><div class="ui blue label">Authenticated</div>
	  </div>
	  <div class="content">
	    <p>This endpoint is responsible for rotating the SSH CA&#39;s public and private keys in the event of them being compromised/expired. After this is done, be sure to quickly update the corresponding SSH Servers with the new <code>ca.pub</code> so that new SSH certificates don&#39;t fail authentication. After the keys are rotated the new private key is flushed to disk in the service&#39;s directory. </p>
	  </div>

	  <div class="title">
	    <i class="dropdown icon"></i>
	    /change_password <div class="ui label">POST</div><div class="ui blue label">Authenticated</div><div class="ui green label">Param: password</div>
	  </div>
	  <div class="content">
        <p>This endpoint is used for changing the password of the service’s Web API. This service is strictly single user and as such only has one user/credential pair. The user is statically <code>admin</code>, the password will default to <code>changeme</code>. When this endpoint is hit the new password will also be flushed to disk in the service&#39;s directory.</p>
	  </div>

	</div>
</div>

<div class="ui raised segment">
  <h2 class="ui dividing icon header">
	<i class="settings icon"></i>
	<div class="content">
	Service Configuration
	<div class="sub header">Learn about how the service operates.</div>
	</div>
  </h2>
  <p>There are basic configuration files that help the SSH CA remain persistent on service/system restart. These files are located in the service&#39;s directory (<code>C:\Program Files (x86)\SSH Certificate Authority</code>). There are two main files: <code>ca.pem</code>(private key) and <code>admin_password</code>(service password). In the event the private key file is missing and the service is restarted, a new public/private key pair will be generated and flushed to disk. If the service password file is missing and the service is restarted, the service will start using the default password.</p>
</div>

<div class="ui raised segment">
  <h2 class="ui dividing icon header">
	<i class="settings icon"></i>
	<div class="content">
	SSH Server Integration
	<div class="sub header">Learn how to configure SSH servers to accept SSH Certificates.</div>
	</div>
  </h2>
  <p>SSH Servers will need to have the <a href="https://man.openbsd.org/sshd_config#TrustedUserCAKeys" target="_blank">TrustedUserCAKeys</a> option set in their configuration file in order for the user certificates to be used as an authentication mechanism. This option should point to a local copy of the SSH CA&#39;s public key (reachable at the <code>/ca.pub</code> endpoint).</p>
</div>

<div class="ui raised segment">
  <h2 class="ui dividing icon header">
	<i class="settings icon"></i>
	<div class="content">
	Using the Certificates
	<div class="sub header">Learn how to use SSH certificates for authentcation</div>
	</div>
  </h2>
  <p>If the service is deployed correctly, then a new form of authentication is available for use when connecting over SSH. Similar to how regular SSH public/private keys operate, you will need to generate a key pair on a client you will wish to connect with. Once you have a key pair you can make a request to the SSH Certificate Authority API at the <code>request_cert</code> endpoint (be sure to choose which user you wish to mint a certificate for carefully!). Then simply place the new user cert with the <code>-cert.pub</code> suffix into the <code>.ssh</code> directory (or wherever your private keys are stored). For example, if the private key file was named <code>id_ecdsa</code> then the SSH certificate would be named <code>id_ecdsa-cert.pub</code>. After that you should be able to SSH directly onto the SSH Server (only for the user you requested the certificate for).</p>
</div>

<div class="ui raised segment">
  <h2 class="ui dividing icon header">
	<i class="key icon"></i>
	<div class="content">
	Keys
	<div class="sub header">Learn about Key Requirements</div>
	</div>
  </h2>
  <p>This project uses <code>ecdsa-sha2-nistp256</code> keys that can be generated via <code>ssh-keygen -t ecdsa -b 256</code>. Any other types of keys are unsupported with the current version of this service.</p>
</div>

<script>
$('.ui.accordion')
  .accordion()
;
</script>

</body>
</html>
`
