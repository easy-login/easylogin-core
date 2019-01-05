import sys
import secrets
from urllib import parse as up
import json
from functools import wraps

from flask import Flask, request, redirect, abort, session, jsonify
from apiclient import EasyLoginClient, ShopifyClient

app = Flask(__name__, template_folder='templates', static_url_path='')
app.config['SECRET_KEY'] = secrets.token_hex(nbytes=32)

ENV = {
    'easylogin-demo.myshopify.com': {
        'easylogin': {
            'app_id': '1',
            'api_key': 'xrcyz2AaN1s9OscnpFLup5DVTi3D7WCIGhYnsmjOyCO8HjAH'
        },
        'shopify': {
            'api_key': 'c1395644900ecc8ecaadebd8f2364e2a',
            'api_secret': 'eaec588f1b6de0444dad30d2e7d48dac'
        }
    },
    'easy-login-tst.myshopify.com': {
        'easylogin': {
            'app_id': '3',
            'api_key': 'qswqIR3y14DnRDgn71F1kVcmgsio0wPPhchZuhJWsNhMBSA2aH44S3AE9ypQWle2'
        },
        'shopify': {
            'api_key': '2100bb975c7b2effa89aa84d6ca39dba',
            'api_secret': '875f94390ee3236b459deccbcc95af7b'
        }
    }
}


@app.route('/hosted/shopify/<shop_url>/auth/callback')
def easylogin_callback(shop_url):
    provider = request.args.get('provider')
    token = request.args.get('token')
    if not provider or not token:
        abort(400, 'Missing or invalid input parameters')
    print(request.url)

    print('Load env for this store', ENV[shop_url])
    easylogin_client = EasyLoginClient(
        app_id=ENV[shop_url]['easylogin']['app_id'],
        api_key=ENV[shop_url]['easylogin']['api_key']
    )
    shopify_client = ShopifyClient(
        shop_url=shop_url,
        api_key=ENV[shop_url]['shopify']['api_key'],
        api_secret=ENV[shop_url]['shopify']['api_secret']
    )

    r = easylogin_client.get_authorized_profile(access_token=token)
    if r.failed:
        raise_error(500, 'EasyLogin API error', data=r.json())

    profile = r.json()
    print('authorized profile', json.dumps(profile, indent=2, ensure_ascii=False))
    attrs = profile.get('attrs', {})
    email = attrs.get('email')
    if not email:
        abort(403, 'Cannot log in without customer email')

    r = shopify_client.search_customer(email=email)
    if r.failed:
        raise_error(500, 'Shopify API error', data=r.json())

    password = secrets.token_hex(nbytes=8)
    customers = r.json()['customers']
    print('shopify customers', customers)

    if customers:
        customer_id = customers[0]['id']
        body = {
            'id': customer_id,
            'password': password,
            'password_confirmation': password
        }
        r = shopify_client.update_customer(customer_id=customer_id, customer=body)
        if r.failed:
            raise_error(500, 'Shopify API error', data=r.json())
        print('update customer info success', r.json()['customer'])
    else:
        first_name = ''
        last_name = email
        if provider == 'line':
            last_name = attrs.get('displayName', last_name)
        elif provider == 'facebook':
            first_name = attrs.get('first_name', first_name)
            last_name = attrs.get('last_name', last_name)
        elif provider == 'yahoojp':
            first_name = attrs.get('given_name', first_name)
            last_name = attrs.get('family_name', last_name)

        body = {
            'customer': {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'verified_email': True,
                'password': password,
                'password_confirmation': password,
                'send_email_welcome': False
            }
        }
        r = shopify_client.create_customer(customer=body)
        if r.failed:
            raise_error(500, 'Shopify API error', data=r.json())
        customer = r.json()['customer']
        customer_id = customer['id']
        print('create customer success', json.dumps(customer, indent=2))

    easylogin_social_id = profile['social_id']
    if not profile.get('user_id'):
        r = easylogin_client.get_user_profile(user_id=customer_id)
        if r.failed:
            if r.status_code != 404:
                print(r.status_code, r.text)
                raise_error(500, 'EasyLogin API error', data=r.json())
            r = easylogin_client.link_social_profile_with_user(
                social_id=easylogin_social_id,
                user_id=customer_id)
            if r.failed:
                raise_error(500, 'EasyLogin API error', data=r.json())
            print('link easylogin social ID with shopify customer ID success',
                  easylogin_social_id, customer_id)
        else:
            r = easylogin_client.merge_user(
                src_social_id=easylogin_social_id,
                dst_user_id=customer_id)
            if r.failed:
                raise_error(500, 'EasyLogin API error', data=r.json())
            print('merge easylogin user success', easylogin_social_id, customer_id)

    params = up.urlencode({'k': email, 's': password, 'a': 'l'})
    return redirect('https://{}/account/login?{}#abc'.format(shop_url, params))


def raise_error(code, msg, data):
    print(code, msg, json.dumps(data, indent=2, ensure_ascii=False))
    abort(code, msg)


def support_jsonp(f):
    """Wraps JSONified output for JSONP"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            content = str(callback) + '(' + f().data.decode('utf8') + ')'
            return app.response_class(content, mimetype='application/json')
        else:
            return f(*args, **kwargs)
    return decorated_function


@app.route('/hosted/shopify/me')
@support_jsonp
def me():
    return jsonify({
        'a': session['action'],
        'k': session['key'],
        's': session['secret']
    })


if __name__ == '__main__':
    port = sys.argv[1] if len(sys.argv) > 1 else 8888
    app.run(host='0.0.0.0', port=port, debug=True)
