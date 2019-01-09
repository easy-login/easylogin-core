(function() {
    $(document).ready(function() {
        var callbackUri = 'https://api.easy-login.jp/hosted/shopify/auth/callback';
        var baseLoginButtonHtml =`
        <div id="SocialAuthForm" class="col-md-6">
            <h4 class="text-center">OR</h4>
            <div class="login-form line-form">
                <a href="https://api.easy-login.jp/auth/line?app_id={{ app_id }}&callback_uri={{ callback_uri }}">
                <button class="line-btn">Login with LINE</button>
                </a>
            </div>
            <div class="login-form yahoo-form">
                <a href="https://api.easy-login.jp/auth/yahoojp?app_id={{ app_id }}&callback_uri={{ callback_uri }}>
                <button class="yahoo-btn">Login with YAHOOJP</button>
                </a>
            </div>
            <div class="login-form facebook-form">
                <a href="https://api.easy-login.jp/auth/facebook?app_id={{ app_id }}&callback_uri={{ callback_uri }}">
                <button class="facebook-btn">Login with FACEBOOK</button>
                </a>
            </div>
        </div>`.replace('{{ callback_uri }}', callbackUri);

        showEasyLoginButtons('EasyLoginButtonContainer', {easyloginAppId: 1})

        function showEasyLoginButtons(container, options) {
            var html = baseLoginButtonHtml.replace('{{ app_id }}', options.easyloginAppId);
            $('#' + container).html(html);
        }

        function getUrlParameter(name) {
            name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
            var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
            var results = regex.exec(location.search);
            return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
        };
  
        function getRequestArgs(name){
            if(name=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(location.search.replace("#_=_", "")))
            return decodeURIComponent(name[1]);
        } 
  
        var action = getUrlParameter('a');
        var email = getUrlParameter('k');
        var password = getUrlParameter('s');
    
        if (action == 'l' && email && password) {
            $('input[name="customer[email]"]').val(email);
            $('input[name="customer[password]"]').val(password);
            $('input[name="customer[email]"]').closest('form').find('input[type=submit]').click();
        }
  
        // $('input[type=submit][value="{{ 'customer.reset_password.submit' | t }}"]').on('click', function() {   
        //     console.log("reset password clicked");
        //     var password = $('input[name="customer[password]"]').val();
        //     var passwordConfirmation = $('input[name="customer[password_confirmation]"]').val();
    
        //     if (password ===a passwordConfirmation) {
    
        //     }
        //     console.log("id:" + $('input[type=hidden][name=id]').val());
        //     console.log("password:" + password);
        // })
    })
})();