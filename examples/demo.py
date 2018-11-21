from flask import Flask, request, render_template, redirect, \
    session, abort, url_for, make_response
import urllib.parse as urlparse
import requests
import json
import random
import secrets
from datetime import datetime, timedelta

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'

APP_ID = 1
API_KEY = 'xrcyz2AaN1s9OscnpFLup5DVTi3D7WCIGhYnsmjOyCO8HjAH'
API_URL = 'https://api.easy-login.jp'


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


@app.route('/app/setting', methods=['POST'])
def app_setting():
    resp = make_response(redirect('/demo.html'))
    _set_cookie(resp, 'api_url', request.form.get('api_url'))
    _set_cookie(resp, 'app_id', request.form.get('app_id'))
    _set_cookie(resp, 'api_key', request.form.get('api_key'))
    return resp


@app.route('/user/<action>', methods=['POST'])
def link_user(action):
    if action not in ['link', 'unlink']:
        abort(400, 'Invalid action')

    user_id = request.form['user_id']
    social_id = request.form['social_id']
    api_url = request.cookies['api_url']
    app_id = request.cookies['app_id']

    url = '{}/{}/users/{}'.format(api_url, app_id, action)
    r = requests.put(url=url, verify=False,
                     json={'user_id': user_id, 'social_id': social_id},
                     headers={'X-Api-Key': request.cookies['api_key']})
    msg = str(r.json())
    return redirect('/demo.html?{}_result={}'.format(action, msg))


@app.route('/auth/<provider>')
def authenticate(provider):
    api_url = request.cookies['api_url']
    demo_url = request.environ.get('HTTP_X_FORWARDED_PROTO', 'http') + '://' + request.host
    qs = {
        'app_id': request.cookies['app_id'],
        'callback_uri': demo_url + '/auth/callback',
        'nonce': secrets.token_hex(16)
    }
    auth_url = '{}/auth/{}?'.format(api_url, provider) + urlparse.urlencode(qs)
    return redirect(auth_url)


@app.route('/auth/callback')
def auth_callback():
    try:
        token = request.args['token']
        provider = request.args['provider']
        api_url = request.cookies['api_url']
        app_id = request.cookies['app_id']
        url = '{}/{}/profiles/authorized'.format(api_url, app_id)

        r = requests.post(url=url, verify=False,
                          json={'token': token},
                          headers={'X-Api-Key': request.cookies['api_key']})
        if r.status_code != 200:
            return redirect('/demo.html')

        profile = r.json()
        session[provider] = json.dumps(profile, sort_keys=True, indent=2)
        if profile['verified']:
            return render_template('result.html',
                                   provider=provider.upper(),
                                   profile=session[provider])
        else:
            attrs = urlparse.quote_plus(json.dumps(profile['attrs'], indent=2))
            resp = make_response(redirect(url_for('register', attrs=attrs)))
            session['token'] = token
            session['provider'] = provider
            return resp
    except KeyError as e:
        print(e)
        return _handle_error()


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        attrs = urlparse.unquote_plus(request.args.get('attrs', ''))
        return render_template('register.html', attrs=attrs)
    else:
        api_url = request.cookies['api_url']
        app_id = request.cookies['app_id']
        provider = session['provider']

        submit = request.form.get('submit', '')
        if 'register' == submit.lower():
            url = '{}/{}/profiles/activate'.format(api_url, app_id)
            r = requests.post(url=url, verify=False,
                              json={'token': session['token']},
                              headers={'X-Api-Key': request.cookies['api_key']})
            if r.status_code == 200:
                profile = json.loads(session[provider], encoding='utf8')
                profile['verified'] = 1
                session[provider] = json.dumps(profile, sort_keys=True, indent=2)
                return render_template('result.html',
                                       provider=provider.upper(),
                                       token=session['token'],
                                       profile=session[provider])
        session[provider] = None
        return redirect('/demo.html')


@app.route('/auth/failed')
def auth_failed():
    return _handle_error()


@app.route('/demo.html')
def index():
    api_url = request.cookies.get('api_url', API_URL)
    app_id = request.cookies.get('app_id', APP_ID)
    api_key = request.cookies.get('api_key', API_KEY)

    view = render_template('demo.html', api_url=api_url, app_id=app_id, api_key=api_key,
                           link_result=request.args.get('link_result', ''),
                           unlink_result=request.args.get('unlink_result', ''),
                           line=session.get('line'),
                           amazon=session.get('amazon'),
                           yahoojp=session.get('yahoojp'),
                           facebook=session.get('facebook'),
                           twitter=session.get('twitter'))
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
    return redirect('/demo.html')


def _set_cookie(resp, key, val):
    resp.set_cookie(key=key, value=str(val),
                    max_age=30 * 24 * 3600,
                    expires=datetime.now() + timedelta(days=30))


def _handle_error():
    error = urlparse.unquote(request.args['error'])
    desc = urlparse.unquote(request.args['error_description'])
    provider = request.args['provider']
    return render_template('error.html', error=error, desc=desc, provider=provider)


if __name__ == '__main__':
    import sys

    port = sys.argv[1] if len(sys.argv) > 1 else 8080
    app.run(host='0.0.0.0', port=port, debug=True)
