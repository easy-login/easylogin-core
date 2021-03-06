from flask import Flask, request, render_template, redirect, jsonify, \
    session, abort, url_for, make_response, send_from_directory
import urllib.parse as urlparse
import requests
import json
import random
import secrets
from datetime import datetime, timedelta
import os
import base64

from amzpay import amazon_pay

app = Flask(__name__, template_folder='templates', static_url_path='/static')
app.config['SECRET_KEY'] = secrets.token_hex(nbytes=32)
app.register_blueprint(amazon_pay, url_prefix='/amazon-pay')

APP_ID = os.getenv('DEFAULT_APP_ID', '1')
API_KEY = os.getenv('DEFAULT_API_KEY', '5kDRiFirpw3MO4y9iXW9AEqDaqdgwMwEfDhQM9iVjuRwsU2R')
API_URL = os.getenv('DEFAULT_API_URL', 'http://localhost:7001')
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


@app.route('/static/js/<path:path>')
def send_js(path):
    return send_from_directory(os.path.join(BASE_DIR, 'static/js'), path)


@app.route('/static/css/<path:path>')
def send_css(path):
    return send_from_directory(os.path.join(BASE_DIR, 'static/css'), path)


@app.route('/images/<path:path>')
def send_images(path):
    return send_from_directory(os.path.join(BASE_DIR, 'images'), path)


@app.route('/')
def homepage():
    return redirect('/demo.html'), 301


@app.route('/chart.html')
def charts():
    return render_template('chart.html',
                           provider_data=[random.randint(200, 1000),
                                          random.randint(200, 1000),
                                          random.randint(200, 1000)],
                           login_data=[random.randint(1000, 2000),
                                       random.randint(200, 1000)])


@app.route('/api-explorer.html')
def api_explorer():
    return render_template('api-explorer.html')


@app.route('/pay.html')
def pay():
    return render_template('pay.html')


@app.route('/app/setting', methods=['POST'])
def app_setting():
    resp = make_response(redirect('/demo.html'))
    _set_cookie(resp, 'api_url', request.form.get('api_url'))
    _set_cookie(resp, 'app_id', request.form.get('app_id'))
    _set_cookie(resp, 'api_key', request.form.get('api_key'))
    return resp


@app.route('/pay/setting', methods=['POST'])
def pay_setting():
    resp = make_response(redirect('/pay.html'))
    _set_cookie(resp, 'amz_client_id', request.form.get('amz_client_id'))
    _set_cookie(resp, 'amz_seller_id', request.form.get('amz_seller_id'))
    return resp


@app.route('/api/<api_name>', methods=['POST'])
def call_api(api_name):
    if api_name not in ['link', 'unlink', 'disassociate', 'profile',
                        'merge', 'associate_token', 'delete_profile', 'delete_info']:
        abort(404, 'Invalid API name')

    api_url = request.cookies['api_url']
    app_id = request.cookies['app_id']
    url = '{}/{}/users/{}'.format(api_url, app_id, api_name)

    if api_name == 'profile':
        url = '{}/{}/users'.format(api_url, app_id)
        r = requests.get(url=url, verify=False, params=request.form,
                         headers={'X-Api-Key': request.cookies['api_key']})
    elif api_name == 'associate_token':
        r = requests.get(url=url, verify=False, params=request.form,
                         headers={'X-Api-Key': request.cookies['api_key']})
    elif api_name == 'delete_profile':
        url = '{}/{}/users'.format(api_url, app_id)
        r = requests.delete(url=url, verify=False, json=request.form,
                            headers={'X-Api-Key': request.cookies['api_key']})
    else:
        r = requests.put(url=url, verify=False, json=request.form,
                         headers={'X-Api-Key': request.cookies['api_key']})
    try:
        msg = r.json()
        if r.status_code != 200:
            msg['status_code'] = r.status_code
    except ValueError as e:
        msg = {'status_code': r.status_code, 'error': str(e)}
    return jsonify(msg)


@app.route('/auth/<provider>')
def authenticate(provider):
    return_url = request.args.get('return_url', '')
    api_url = request.cookies['api_url']
    demo_url = request.environ.get('HTTP_X_FORWARDED_PROTO', 'http') + '://' + request.host
    qs = {
        'app_id': request.cookies['app_id'],
        'callback_uri': demo_url + '/auth/callback?return_url=' + urlparse.quote_plus(return_url),
        'nonce': secrets.token_hex(16),
        'sandbox': request.args.get('sandbox', '')
    }
    auth_url = '{base_url}/auth/{provider}/{intent}?'.format(
        base_url=api_url,
        provider=provider,
        intent=request.args.get('intent', 'auth')
    ) + urlparse.urlencode(qs)
    return redirect(auth_url)


@app.route('/auth/callback')
def auth_callback():
    try:
        provider = request.args['provider']
        token = request.args['token']
        api_url = request.cookies['api_url']
        url = '{}/auth/profiles/authorized'.format(api_url, )

        r = requests.post(url=url, verify=False,
                          data={
                              'auth_token': token,
                              'api_key': request.cookies['api_key']
                          })
        if r.status_code != 200:
            return redirect('/demo.html')

        return_url = request.args.get('return_url')
        if return_url:
            return redirect(return_url)

        profile = r.json()
        session[provider] = json.dumps(profile, sort_keys=True, indent=2, ensure_ascii=False)
        if profile['verified']:
            return render_template('success.html',
                                   provider=provider.upper(),
                                   profile=session[provider])
        else:
            attrs = urlparse.quote_plus(json.dumps(profile['attrs'], indent=2, ensure_ascii=False))
            resp = make_response(redirect(url_for('register', attrs=attrs)))
            session['token'] = token
            session['provider'] = provider
            return resp
    except KeyError as e:
        print(e)
        return _handle_error(provider=request.args.get('provider', 'unknown'), error=str(e))


@app.route('/auth/failed')
def auth_failed():
    return _handle_error()


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        attrs = urlparse.unquote_plus(request.args.get('attrs', ''))
        return render_template('register.html', attrs=attrs)
    else:
        api_url = request.cookies['api_url']
        provider = session['provider']
        submit = request.form.get('submit', '')
        if 'register' == submit.lower():
            url = '{}/auth/profiles/activate'.format(api_url)
            r = requests.post(url=url, verify=False,
                              data={
                                  'auth_token': session['token'],
                                  'api_key': request.cookies['api_key']
                              })
            if r.status_code == 200:
                profile = json.loads(session[provider], encoding='utf8')
                profile['verified'] = 1
                session[provider] = json.dumps(profile, sort_keys=True, indent=2)
                return render_template('success.html',
                                       provider=provider.upper(),
                                       token=session['token'],
                                       profile=session[provider])
            else:
                return _handle_error(error=json.dumps({
                    'status_code': r.status_code,
                    'data': r.json()
                }, indent=2), provider=provider)
        session[provider] = None
        return redirect('/demo.html')


@app.route('/demo.html')
def index():
    api_url = request.cookies.get('api_url', API_URL)
    app_id = request.cookies.get('app_id', APP_ID)
    api_key = request.cookies.get('api_key', API_KEY)

    view = render_template('demo.html', api_url=api_url, app_id=app_id, api_key=api_key)
    resp = make_response(view)
    _set_cookie(resp, 'api_url', api_url)
    _set_cookie(resp, 'app_id', app_id)
    _set_cookie(resp, 'api_key', api_key)
    return resp


@app.route('/logout')
def logout():
    session['line'] = None
    session['amazon'] = None
    session['yahoojp'] = None
    session['facebook'] = None
    session['twitter'] = None
    session['google'] = None
    return redirect('/demo.html')


def _set_cookie(resp, key, val):
    resp.set_cookie(key=key, value=str(val),
                    max_age=30 * 24 * 3600,
                    expires=datetime.now() + timedelta(days=30))


def _handle_error(provider=None, error=None):
    provider = provider or request.args['provider']
    error = error or json.dumps({
        'error': urlparse.unquote(request.args['error']),
        'error_description': urlparse.unquote(request.args['error_description'])
    }, indent=2)
    return render_template('error.html', error=error, provider=provider.upper())


def base64encode(b, urlsafe=False, padding=True):
    ob = base64.urlsafe_b64encode(b) if urlsafe else base64.standard_b64encode(b)
    encoded = ob.decode('ascii')
    if not padding:
        encoded = encoded.rstrip('=')
    return encoded


def base64decode(s, urlsafe=False):
    padding = 4 - (len(s) % 4)
    s += ('=' * padding)
    b = s.encode('ascii')
    ob = base64.urlsafe_b64decode(b) if urlsafe else base64.standard_b64decode(b)
    return ob


def b64encode_string(s, urlsafe=False, padding=True, charset='utf8'):
    b = s.encode(charset)
    return base64encode(b, urlsafe, padding)


def b64decode_string(s, urlsafe=False, charset='utf8'):
    ob = base64decode(s, urlsafe)
    return ob.decode(charset)


if __name__ == '__main__':
    import sys

    port = sys.argv[1] if len(sys.argv) > 1 else 8080
    debug_mode = bool(os.getenv('DEBUG', 1))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
