(function() {
  function isDefined(v) {
    return (typeof v !== 'undefined');
  }

  function getQueryParams() {
    var qs = window.location.search;
    qs = qs.split("+").join(" ");

    var params = {}, tokens,
        re = /[?&]?([^=]+)=([^&]*)/g;

    while (tokens = re.exec(qs)) {
      params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
    }

    return params;
  }

  function getUrlParameter(name) {
    name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
    var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
    var results = regex.exec(location.search);
    return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
  };

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

      var checkoutUrl = getUrlParameter('checkout_url');
      if (checkoutUrl) {
        $('#SocialAuthForm a').each(function() {
          var $this = $(this);
          var _href = $this.attr("href");
          $this.attr("href", _href + '?return_url=' + checkoutUrl);
        });
      }
    });
  };

  function login(params) {
    var form = document.createElement('form');
    form.setAttribute('method', 'post');
    form.setAttribute('action', '/account/login');

    for (var key in params) {
      var field = document.createElement('input');
      field.setAttribute('type', 'hidden');
      field.setAttribute('name', key);
      field.setAttribute('value', params[key]);
      form.appendChild(field);
    }

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
  };

  function checkStartEasyLogin() {
    var path = window.location.pathname;
    if (path !== '/account/login' && path !== '/account/register') return;

    addCss('https://s3-ap-northeast-1.amazonaws.com/static.easy-login.jp/shopify/easylogin-shopify.scss');
    showEasyLoginButtons('EasyLoginContainer');

    var queryParams = getQueryParams();
    var email = queryParams.k;
    var password = queryParams.s;
    var returnUrl = queryParams.r;

    if (isDefined(email) && isDefined(password)) {
      var params = {
        'customer[email]': email,
        'customer[password]': password,
        'form_type': 'customer_login',
        'utf8': 'âœ“'
      };
      if (isDefined(returnUrl)) {
        params['return_to'] = returnUrl.replace('https://' + Shopify.shop, '');
      }
      login(params);
    }
  };

  $(document).ready(function() {
    console.log('Current Shopify shop: ' + Shopify.shop);     
    checkStartEasyLogin();
  })
})();