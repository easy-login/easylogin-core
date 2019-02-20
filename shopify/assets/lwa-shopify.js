(function () {

    function addListener(element, eventName, fn) {
        window.attachEvent ? element.attachEvent('on' + eventName, fn) : element.addEventListener(eventName, fn, false);
    }

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

    // Register message listener that handles login/password messages from LwA
    var receiveMessageFn = function (e) {
        var origin = e.origin;
        var data = e.data;

        if (origin.indexOf('://' + window.location.hostname) == -1 &&
                origin.indexOf('://thexba.net') == -1 &&
                origin.indexOf('https://hosted.loginwithamazon.com') == -1 &&
                origin.indexOf('https://hosted-gamma.loginwithamazon.com') == -1 &&
                origin.indexOf('https://hosted-integ.loginwithamazon.com') == -1) {
            return;
        }

        if (!isDefined(data) || !isDefined(data.src) || data.src !== 'lwa') {
            return;
        }


        var queryParams = getQueryParams();
        var isCheckoutPage = isDefined(queryParams.checkout_url);

        var params = {
            'customer[email]': data.email,
            'customer[password]': data.password,
            'form_type': 'customer_login',
            'utf8': 'âœ“'
        };

        if (isCheckoutPage) {
        	var checkoutUrl = queryParams.checkout_url;
        	var cart = window.location.pathname.split('/')[3];

        	params['checkout_url'] = checkoutUrl;
        	params['cart'] = cart;

        } else {
            var returnTo = data.returnTo;

            if (returnTo == '') {
                returnTo = '/account';
            }

	        params['return_to'] = returnTo;
        }

        login(params);
        return true;
    };

    function fixLwaImage(el) {
        try {
            var children = el.children;
            if (isDefined(children)) {
                for (var j = 0; j < children.length; j++) {
                    var child = children[j];
                    var attrsToAdd = [];

                    if (child.tagName == 'IMG') {
                        var attrs = child.attributes;
                        for (var attrIdx = 0; attrIdx < attrs.length; attrIdx++) {
                            var attr = attrs[attrIdx];
                            var nodeName = attr.nodeName;

                            if (nodeName.charCodeAt(0) == 160) {
                                var cleanNodeName = nodeName.replace(/\xA0*/g, '');
                                child.setAttribute(cleanNodeName, attr.nodeValue);
                            }
                        }
                    }
                }
            }
        } catch (e) {
            console.log(e);
        }
    };

    // Attach click handler to the LwA button
    var attachToLinkFn = function (e) {
        var shopEncoded = encodeURIComponent(Shopify.shop);
        var lwaButtonClickFn = function (e) {
            e.preventDefault() && e.stopPropagation();

            var l = window.location;
            var siteUrl = l.protocol + '//' + l.host;
            var popupUrl = siteUrl + '/apps/lwa?origin=' + encodeURIComponent(siteUrl);
            var options = 'toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=0,resizable=0,copyhistory=no,width=800,height=540';
            window.open(popupUrl, 'Login with Amazon', options);
        };

        var elements = document.getElementsByClassName('login-with-amazon');

        if (isDefined(elements)) {
            for (var i = 0; i < elements.length; i++) {
                var el = elements[i];
                fixLwaImage(el);
                addListener(el, 'click', lwaButtonClickFn);
            }
        }
    };

    addListener(window, 'message', receiveMessageFn);
    addListener(window, 'load', attachToLinkFn);
})();