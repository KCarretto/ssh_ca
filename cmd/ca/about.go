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
  <a href="/">
    <h2 class="ui header">
      <i class="key blue icon"></i>
      <div class="content">
        SSH Certificate Authority
        <div class="sub header">Providing Secure Authentication</div>
      </div>
    </h2>
  </a>
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

<div class="ui raised very padded segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue coffee icon"></i>
	<div class="content">
	Overview
	<div class="sub header">What is the SSH Certificate Authority?</div>
	</div>
  </h2>
  <p>
  Welcome to the SSH Certificate Authority!
  This HTTP service is responsible for issuing new SSH User Certificates to users that wish to connect to our Linux infrastructure.
  Any SSH User Certificate signed by this SSH Certificate Authority will be able to authenticate to Linux hosts in our environment.
  More information on the implementation of the SSH Certificate Authority &amp; configuration requirements for SSH Servers can be found below.</p>
</div>


<div class="ui raised very padded blue segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue cloud upload icon"></i>
	<div class="content">
	API
	<div class="sub header">Learn about our HTTP API.</div>
	</div>
  </h2>

  <p>The service hosts 6 HTTP endpoints on port <code>8080</code>. Some endpoints of the API are secured with HTTP Basic Authentication.</p>
	<div class="ui styled fluid accordion">

	  <div class="active title">
		<i class="dropdown icon"></i>
		/ <div class="ui label">GET</div><div class="ui teal label">Unauthenticated</div>
	  </div>
	  <div class="active content">
	    <p>Displays information about the service and enables the following actions:
		<ul>
		<li>Requesting new SSH User Certificates</li>
		<li>Rotating the CA's public & private keys</li>
		<li>Changing the service password</li>
		</ul>
		</p>
	  </div>

	  <div class="title">
		<i class="dropdown icon"></i>
		/about <div class="ui label">GET</div><div class="ui teal label">Unauthenticated</div>
	  </div>
	  <div class="content">
	  	<p>Provides mission critical operational intel on the configuration, behaviour, and cyber effects of the SSH Certificate Authority.</p>
	  </div>

	  <div class="title">
		<i class="dropdown icon"></i>
		/ca.pub <div class="ui label">GET</div><div class="ui teal label">Unauthenticated</div>
	  </div>
	  <div class="content">
	    <p>Used for retrieving the SSH Certificate Authority's public key. This file must be synchronized across all SSH Servers for SSH authentication to properly function. This endpoint is unauthenticated, so system administrators may easily <code>curl</code> this endpoint to retrieve an updated SSH Certificate Authority public key.</p>
	  </div>

	  <div class="title">
		<i class="dropdown icon"></i>
		/request_cert <div class="ui label">GET</div><div class="ui blue label">Authenticated</div><div class="ui green label">Query Param: b64pubkey</div><div class="ui green label">Query Param: user</div>
	  </div>
	  <div class="content">
		<p>Signs an SSH User Certificate for the given user. The first query parameter is a base64 encoded ECDSA P256 SSH public key.
		<br/><br/><br/>As an example, if an SSH public key is:<br/>
		<code>
			ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA<br/>
			IbmlzdHAyNTYAAABBBDW+M8gDB+ZX3/PPyGGiNgDItvw3O42vnw43th<br/>
			8zhhoKtWfqzqxy8OrjrcG4NWx0WbD/b1D92PzreiMaSuaxU24= <br/>
			user@localhost.localdomain
		</code>
		<br/><br/>Then this value should be:<br/>
		<code>
			ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJ<br/>
			tbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1<br/>
			pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4e<br/>
			ThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290<br/>
			QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo=
		</code>
		<br/><br/>The second query param is the unixname that the SSH User Certificate will be valid for (e.g. <code>root</code>).
		</p>
	  </div>

	  <div class="title">
	    <i class="dropdown icon"></i>
	    /rotate <div class="ui label">POST</div><div class="ui blue label">Authenticated</div>
	  </div>
	  <div class="content">
	    <p>Rotates the SSH Certificate Authority's public and private keys. These keys should be rotated immediately in the event of compromise. To minimize downtime, quickly update the corresponding SSH Servers to use the new <a href="/ca.pub">ca.pub</a> (SSH Authentication will fail until you do so). After the keys have been rotated the new SSH Certificate Authority private key is written to disk in the service&#39;s directory. </p>
	  </div>

	  <div class="title">
	    <i class="dropdown icon"></i>
	    /change_password <div class="ui label">POST</div><div class="ui blue label">Authenticated</div><div class="ui green label">Param: password</div>
	  </div>
	  <div class="content">
        <p>Changes the password of the service’s Web API. This service only has a single user (<code>admin</code>). This endpoint saves the password to disk in the service's directory. </p>
	  </div>

	</div>
</div>

<div class="ui raised very padded blue segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue settings icon"></i>
	<div class="content">
	Service Configuration
	<div class="sub header">Learn how the service operates.</div>
	</div>
  </h2>
  <p>There are basic configuration files that help the SSH Certificate Authority remain persistent on service/system restart.</p>
  <div class="ui styled fluid accordion">
    <div class="active title">
	<i class="dropdown icon"></i>
		Important Files
	</div>
	<div class="active content">
	  <table class="ui celled table">
  		<thead>
    	  <tr>
		    <th>Name</th>
    	    <th>Location</th>
    	    <th>Description</th>
  		  </tr>
		</thead>
  		<tbody>
    	  <tr>
      		<td data-label="Name">SSH CA Private Key</td>
      		<td data-label="Location"><code>C:\Program Files (x86)\SSH Certificate Authority\ca.pem</code></td>
      		<td data-label="Description">PEM encoded ECDSA P256 Private key used by the SSH Certificate Authority to sign SSH User Certificates. If it does not exist when the service is started, a new key will be generated and written to this file.</td>
    	  </tr>
		  <tr>
      		<td data-label="Name">Admin Password</td>
      		<td data-label="Location"><code>C:\Program Files (x86)\SSH Certificate Authority\admin_password</code></td>
      		<td data-label="Description">Password used for HTTP Basic Authentication to access this web application. If it does not exist when the service is started, the default credentials will be used and written to this file.</td>
    	  </tr>
		</tbody>
	  </table>
	</div>
	<div class="title">
	<i class="dropdown icon"></i>
		Service Logs
	</div>
	<div class="content">
	This service logs all requests and important state changes to Windows Event Log.
	<table class="ui celled table">
		<thead>
			<tr>
			<th>Event ID</th>
			<th>Type</th>
			<th>Description</th>
			</tr>
		</thead>
		<tbody>
		<tr>
			<td data-label="Event ID">1</td>
			<td data-label="Type">Service Control Signals</td>
			<td data-label="Description">Control signals received by this service (e.g. <code>start</code> / <code>shutdown</code>).</td>
		</tr>
		<tr>
			<td data-label="Event ID">2</td>
			<td data-label="Type">General</td>
			<td data-label="Description">General log messages.</td>
		</tr>
		<tr>
			<td data-label="Event ID">22</td>
			<td data-label="Type">State Changes</td>
			<td data-label="Description">Important application state changes (e.g. password change).</td>
		</tr>
		<tr>
			<td data-label="Event ID">80</td>
			<td data-label="Type">Web Requests</td>
			<td data-label="Description">HTTP requests handled by the server.</td>
		</tr>
	</tbody>
	</table>
	</div>
    <div class="title">
	  <i class="dropdown icon"></i>
		Default Credentials
	</div>
	<div class="content">
		<b>Username:  </b><code>admin</code><br/>
		<b>Password:  </b><code>changeme</code>
	</div>
  </div>
</div>

<div class="ui raised very padded blue segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue server icon"></i>
	<div class="content">
	SSH Server Integration
	<div class="sub header">Learn how to configure SSH servers to accept SSH User Certificates.</div>
	</div>
  </h2>
  <p>SSH Servers will need to have the <a href="https://man.openbsd.org/sshd_config#TrustedUserCAKeys" target="_blank">TrustedUserCAKeys</a> option set in their configuration file in order for the SSH User Certificates to be used as an authentication mechanism. This option should point to a local copy of the SSH Certificate Authority's public key (which can be found <a href="/ca.pub">here</a>).</p>
</div>

<div class="ui raised very padded blue segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue address card icon"></i>
	<div class="content">
	Using the Certificates
	<div class="sub header">Learn how to use SSH User Certificates for authentication</div>
	</div>
  </h2>
  <p>If the service is deployed correctly, then a new form of authentication is available for use when connecting over SSH. Similar to how regular SSH public/private keys operate, you will need to generate a key pair on the client you wish to connect with. Once you have a key pair you can make a request to the SSH Certificate Authority API using the <code>request_cert</code> endpoint. Next, place the new SSH User Certificate with a <code>-cert.pub</code> suffix into the <code>.ssh</code> directory (or wherever your private keys are stored). For example, if the private key file was named <code>id_ecdsa</code> then the SSH User Certificate would be named <code>id_ecdsa-cert.pub</code>. After that you should be able to SSH to Linux machines in our environment as the user you requested the SSH User Certificate for.</p>
</div>

<div class="ui raised very padded blue segment">
  <h2 class="ui dividing icon center aligned header">
	<i class="blue key icon"></i>
	<div class="content">
	Keys
	<div class="sub header">Learn about Key Requirements</div>
	</div>
  </h2>
  <p>This service uses <code>ecdsa-sha2-nistp256</code> keys that can be generated via <code>ssh-keygen -t ecdsa -b 256</code>. All other key type are unsupported.</p>
</div>

<script>
$('.ui.accordion')
  .accordion()
;
</script>

</body>
</html>
`
