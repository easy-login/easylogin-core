$(document).ready(function() {
    var socialAuthForm = `
    <div id="SocialAuthForm" class="col-md-6">
        <h4 class="text-center">OR</h4>
    </div>      
    `;
    var lineForm = `
    <div class="loginForm line-form">
        <form action="https://api.easy-login.jp/auth/line" method="get">
            <input type="hidden" name="callback_uri" value="http://45ee95ff.ngrok.io/hosted/shopify/easylogin-demo.myshopify.com/auth/callback"/>
            <input type="hidden" name="app_id" value="1"/>
            <input class="line-btn" type="submit" value="Login with LINE" name="submit"/>
        </form>
    </div>`;

    function loadSocialLoginButtons(container, options) {
        var appId = options.appId;
        var callbackUrl = options.callbackUrl;
        
    }

    function getRequestArgs(name){
      if(name=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(location.search))
        return decodeURIComponent(name[1]);
    } 
    
    var action = getRequestArgs('a');
    var email = getRequestArgs('k');
    var password = getRequestArgs('s');
    
    if (action === 'l') {
      $('input[name="customer[email]"]').val(email);
      $('input[name="customer[password]"]').val(password);
      $('input[type=submit][value="{{ 'customer.login.sign_in' | t }}"]').click();
    } else if (action === 'r') {
      var firstName = getRequestArgs('f');
      var lastName = getRequestArgs('l');
      
      $('input[name="customer[first_name]"]').val(firstName);
      $('input[name="customer[last_name]"]').val(lastName);
      $('input[name="customer[email]"]').val(email);
      $('input[name="customer[password]"]').val(password);
      $('input[type=submit][value="{{ 'customer.register.submit' | t }}"]').click();
    }
  
    $('input[type=submit][value="{{ 'customer.reset_password.submit' | t }}"]').on('click', function() {   
      console.log("reset password clicked");
      var password = $('input[name="customer[password]"]').val();
      var passwordConfirmation = $('input[name="customer[password_confirmation]"]').val();
  
      if (password === passwordConfirmation) {
  
      }
      console.log("id:" + $('input[type=hidden][name=id]').val());
      console.log("password:" + password);
    })
  });