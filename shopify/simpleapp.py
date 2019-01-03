import sys
import os
import requests
import secrets
from urllib import parse as up

from flask import Flask, request, redirect, jsonify, abort

app = Flask(__name__, template_folder='templates', static_url_path='')
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'

EASYLOGIN_APP_ID = os.getenv('EASYLOGIN_APP_ID', '1')
EASYLOGIN_API_KEY = os.getenv('EASYLOGIN_API_KEY', 'xrcyz2AaN1s9OscnpFLup5DVTi3D7WCIGhYnsmjOyCO8HjAH')
EASYLOGIN_API_ENDPOINT = os.getenv('EASYLOGIN_API_ENDPOINT', 'https://api.easy-login.jp')

SHOPIFY_STORE = os.getenv('SHOPIFY_STORE', 'easylogin-demo.myshopify.com')
SHOPIFY_API_KEY = os.getenv('SHOPIFY_API_KEY', 'c1395644900ecc8ecaadebd8f2364e2a')
SHOPIFY_API_SECRET = os.getenv('SHOPIFY_API_SECRET', 'eaec588f1b6de0444dad30d2e7d48dac')
SHOPIFY_API_ENDPOINT = 'https://{}:{}@{}'.format(SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_STORE)


@app.route('/easylogin/auth/callback')
def easylogin_callback():
    provider = request.args.get('provider')
    token = request.args.get('token')
    if not provider or not token:
        abort(400, 'Missing or invalid input parameters')

    easylogin_profile_url = '{}/{}/profiles/authorized'.format(
        EASYLOGIN_API_ENDPOINT,
        EASYLOGIN_APP_ID)
    r = requests.post(url=easylogin_profile_url, verify=False,
                      json={'token': token},
                      headers={'X-Api-Key': EASYLOGIN_API_KEY})
    if r.status_code != 200:
        print(r.status_code, r.text)
        abort(500, 'EasyLogin API error')

    profile = r.json()
    attrs = profile.get('attrs', {})
    print('attrs', attrs)
    email = attrs.get('email')
    if not email:
        abort(403, 'Cannot log in without customer email')

    shopify_customer_search_url = '{}/admin/customers/search.json?query=email:{}&fields=id'.format(
        SHOPIFY_API_ENDPOINT,
        email)
    r = requests.get(url=shopify_customer_search_url)
    if r.status_code != 200:
        print(r.status_code, r.text)
        abort(500, 'Shopify API error')

    customers = r.json()['customers']
    print('shopify customers', customers)
    if customers:
        customer_id = customers[0]['id']
        password = secrets.token_hex(nbytes=8)
        shopify_update_customer_url = '{}/admin/customers/{}.json'.format(
            SHOPIFY_API_ENDPOINT,
            customer_id)
        print(shopify_update_customer_url)
        body = {
            'customer': {
                'id': customer_id,
                'password': password,
                'password_confirmation': password
            }
        }
        r = requests.put(url=shopify_update_customer_url, json=body)
        if r.status_code != 200:
            print(r.status_code, r.text)
            abort(500, 'Shopify API error')
        print('update customer info success', r.json())

        params = up.urlencode({'a': 'l', 'k': email, 's': password})
        return redirect('https://{}/account/login?{}'.format(SHOPIFY_STORE, params))
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

        password = secrets.token_hex(nbytes=8)
        shopify_create_customer_url = '{}/admin/customers.json'.format(SHOPIFY_API_ENDPOINT)
        body = {
            'customer': {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': password,
                'password_confirmation': password,
                'send_email_welcome': False
            }
        }
        r = requests.post(url=shopify_create_customer_url, json=body)
        if r.status_code != 201:
            print(r.status_code, r.text)
            abort(500, 'Shopify API error')
        print('create customer success', r.json())

        params = up.urlencode({'a': 'l', 'k': email, 's': password})
        return redirect('https://{}/account/login?{}'.format(SHOPIFY_STORE, params))
        # params = up.urlencode({'a': 'r', 'k': email, 's': password,
        #                        'f': first_name, 'l': last_name})
        # return redirect('https://{}/account/register?{}'.format(SHOPIFY_STORE, params))


if __name__ == '__main__':
    import sys

    port = sys.argv[1] if len(sys.argv) > 1 else 8888
    app.run(host='0.0.0.0', port=port, debug=True)
