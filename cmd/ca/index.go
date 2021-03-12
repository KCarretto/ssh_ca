package main

const IndexHTML = `
<!DOCTYPE html>
<html>
<body>

<h1>SSH Certificate Authority</h2>
<p> Welcome to the SSH Certificate Authority (CA)! This HTTP service is responsible for issuing new SSH certificates to clients that wish to connect to our Linux infrastructure. Our CA Public Key (which can be found <a href="/ca.pub">here</a>) is deployed to all Linux machines in our environment. Any SSH certificate signed by this CA will be able to authenticate to Linux hosts in our environment via SSH.</p>


<h2>Tools</h2>

<h3>Request SSH Certificate</h3>
<p>Paste a Base64 Encoded ECDSA P256 Public Key (consider using <code>ssh-keygen -t ecdsa -b 256</code> followed by <code>cat ~/.ssh/id_ecdsa.pub | base64</code>) that can be used for SSH authentication for the provided user. Be sure to provide the public key and <b>not</b> the private key.</p>
<form action="/request_cert">
  <label for="user">User</label>
  <input type="text" id="user" name="user" value="root">
  <br/>
  <br/><label for="b64pubkey">Base64 Encoded ECDSA P256 Public Key</label>
  <br/><textarea id="b64pubkey" name="b64pubkey" rows="6" cols="25"></textarea>
  <br/>
  <input type="submit" value="Request">
</form>

<h3>Rotate Keys</h3>
<p> This button will generate a new ECDSA keypair that the SSH Certificate Authority will use to sign new certificates. For authentication to continue working, SSH servers must update their <a href="https://man.openbsd.org/sshd_config#TrustedUserCAKeys" target="_blank">TrustedUserCAKeys</a> to use the new CA public key (which can be found <a href="/ca.pub">here</a>).</p>
<form action="/rotate" method="POST">
  <input type="submit" value="Rotate Keys">
</form>

<h3>Change Password</h3>
<p> Use the below form to change the admin password for this SSH Certificate Authority service.</p>
<form action="/change_password" method="POST">
  <label for="password">New Password</label>
  <input type="password" id="password" name="password" value="">
  <input type="submit" value="Submit">
</form>

</body>
</html>

`
