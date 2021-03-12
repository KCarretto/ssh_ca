package main

const IndexHTML = `
<!DOCTYPE html>
<html>
<body>

<h1>SSH Certificate Authority</h2>
<p> Welcome to the SSH Certificate Authority (CA)! This HTTP service is responsible for issuing new SSH certificates to clients that wish to connect to our Linux infrastructure. Our CA Public Key (which can be found <a href="/ca.pub">here</a>) is deployed to all Linux machines in our environment. Any SSH certificate signed by this CA will be able to authenticate to Linux hosts in our environment via SSH.</p>

</body>
</html>

`
