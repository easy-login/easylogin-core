(function() {
  function addCss(fileName) {
    var head = document.head;
    var link = document.createElement("link");

    link.type = "text/css";
    link.rel = "stylesheet";
    link.href = fileName;

    head.appendChild(link);
  }
  
  function showEasyLoginButtons(container) {
    $.ajax({
      url: 'https://api.easy-login.jp/shopify/{shop}/buttons'.replace('{shop}', Shopify.shop),
      jsonp: 'callback',
      dataType: 'jsonp'     
    }).done(function(data) {
      if (document.getElementById(container)) {
        $('#' + container).html(data.html);
      } else {
        $('input[name="customer[email]"]').closest('form').parent().append(data.html);
      }
    });
  };

  function checkStartEasyLogin() {
    var path = window.location.pathname;
    if (path !== '/account/login' && path !== '/account/register') return;

    addCss('https://s3-ap-northeast-1.amazonaws.com/static.easy-login.jp/shopify/easylogin-shopify.scss');
    showEasyLoginButtons('EasyLoginContainer');

    var email = getUrlParameter('k');
    var password = getUrlParameter('s');

    if (email && password) {
      $('input[name="customer[email]"]').val(email);
      $('input[name="customer[password]"]').val(password);
      $('input[name="customer[email]"]').closest('form').find('input[type=submit]').click();
    }
  };

  function getUrlParameter(name) {
    name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
    var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
    var results = regex.exec(location.search);
    return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
  };

  function getRequestArgs(name) {
    if(name=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(location.search.replace("#_=_", "")))
      return decodeURIComponent(name[1]);
  };
    
  $(document).ready(function() {
    console.log('Current Shopify shop: ' + Shopify.shop);     
    checkStartEasyLogin();
     
//     $('input[type=submit][value="{{ 'customer.reset_password.submit' | t }}"]').on('click', function() {   
//       console.log("reset password clicked");
//       var password = $('input[name="customer[password]"]').val();
//       var passwordConfirmation = $('input[name="customer[password_confirmation]"]').val();

//       if (password === passwordConfirmation) {

//       }
//       console.log("id:" + $('input[type=hidden][name=id]').val());
//       console.log("password:" + password);
//     })
  })
})();