package main

const IndexHTML = `
<!DOCTYPE html>
<html>
<head>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.js" integrity="sha512-dqw6X88iGgZlTsONxZK9ePmJEFrmHwpuMrsUChjAw1mRUhUITE5QU9pkcSox+ynfLhL15Sv2al5A0LVyDCmtUw==" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.js" integrity="sha512-VEd+nq25CkR676O+pLBnDW09R7VQX9Mdiij052gVCp5yVH3jGtH70Ho/UUv4mJDsEdTvqRCFZg0NKGiojGnUCw==" crossorigin="anonymous"></script>

  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.css" integrity="sha512-3pIirOrwegjM6erE5gPSwkUzO+3cTjpnV9lexlNZqvupR64iZBnOOTiiLPb9M36zpMScbmUNIcHUqKD47M719g==" crossorigin="anonymous" />
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

<div class="ui centered three column grid padded">
  <div class="ten wide column">
    <div class="ui raised fluid blue card">
      <div class="content">
        <h3 class="header">Request SSH Certificate</h3>
        <form class="ui form" action="/request_cert" id="request_cert_form">
          <div class="field">
            <div class="ui labeled input">
              <div class="ui label">
                User
              </div>
              <input type="text" id="user" name="user" placeholder="root">
            </div>
          </div>
          <div class="field">

            <label for="b64pubkey">Base64 Encoded ECDSA P256 Public Key
              <i id="keypopup" class="blue question icon"></i>
              <div class="ui flowing popup top left transition hidden">
                Consider using: <code>ssh-keygen -t ecdsa -b 256</code><br/>
                followed by: <code>cat ~/.ssh/id_ecdsa.pub | base64</code>
                </div>
            </label>

            <textarea id="b64pubkey" name="b64pubkey" rows="6" cols="25" placeholder="ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkRXK004Z0RCK1pYMy9QUHlHR2lOZ0RJdHZ3M080MnZudzQzdGg4emhob0t0V2ZxenF4eThPcmpyY0c0Tld4MFdiRC9iMUQ5MlB6cmVpTWFTdWF4VTI0PSByb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgo="></textarea>
          </div>
          <input class="ui blue right floated button" type="submit" value="Request">
        </form>
      </div>
    </div>
  </div>

  <div class="six wide column">
    <div class="ui raised fluid blue card">
      <div class="content">
        <h3 class="header">Rotate Keys</h3>
        <p>Generates a new ECDSA keypair that the SSH Certificate Authority will use to sign new certificates. For authentication to continue working, SSH servers must update their <a href="https://man.openbsd.org/sshd_config#TrustedUserCAKeys" target="_blank">TrustedUserCAKeys</a> to use the new CA public key (which can be found <a href="/ca.pub">here</a>).</p><br/>
        <form class="ui form" action="/rotate" method="POST" id="rotate_form">
          <input class="ui blue floated right button" type="submit" value="Rotate Keys">
        </form>
      </div>
    </div>

    <div class="ui raised fluid blue card">
      <div class="content">
        <h3 class="header">Change Admin Password</h3>
        <form class="ui form" action="/change_password" method="POST" id="change_password">
          <div class="inline field">
            <div class="ui labeled input">
              <div class="ui label">
                New Password
              </div>
              <input type="password" id="new_password" name="password" value="">
            </div>
            <br /><br />
            <div class="ui labeled input">
              <div class="ui label">
                Confirm Password
              </div>
              <input type="password" id="confirm_password" name="password" value="">
            </div>
            <input class="ui blue button" type="submit" value="Submit">
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<script>
  $('#keypopup').popup();

  toastr.options = {
    "closeButton": true,
    "debug": false,
    "newestOnTop": false,
    "progressBar": true,
    "positionClass": "toast-bottom-full-width",
    "preventDuplicates": false,
    "onclick": null,
    "showDuration": "1000",
    "hideDuration": "1000",
    "timeOut": "5000",
    "extendedTimeOut": "1000",
    "showEasing": "swing",
    "hideEasing": "linear",
    "showMethod": "fadeIn",
    "hideMethod": "fadeOut"
  }

  $('#request_cert_form').submit(function(event){
    let user = event.currentTarget.elements[0].value;
    let pubkey = event.currentTarget.elements[1].value;
    if (user == "") {
      event.preventDefault();
      toastr["error"]("Please input a user for the certificate", "Request SSH Certificate");
    }
    if (pubkey == "") {
      event.preventDefault();
      toastr["error"]("Please input a public key for the certificate", "Request SSH Certificate");
    }
  });

  $('#rotate_form').submit(function(event){
    event.preventDefault();
    let r = confirm('Are you sure you wish to rotate the CA\'s keys?');
    if (!r) {
      return;
    }
    $.post('/rotate', function(result, statusText, xhr){
      if (xhr.status == 200) {
        toastr["success"](result, "Rotation Keys");
        return;
      }
      toastr["error"](result, "Rotation Keys");
    });
  });

  $('#change_password').submit(function(event){
    event.preventDefault();
    if ($('#new_password').serialize() != $('#confirm_password').serialize()) {
      toastr["error"]("The two entered passwords are not the same", "Change Admin Password");
      return;
    }
    $.post('/change_password', $('#change_password').serialize(), function(result, statusText, xhr){
      if (xhr.status == 200) {
        toastr["success"](result, "Change Admin Password");
        return;
      }
      toastr["error"](result, "Change Admin Password");
    });
  });
</script>

</body>
</html>
`
