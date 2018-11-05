from flask import Flask, request, render_template, redirect, session, abort
import urllib.parse as urlparse
import requests
import json
import random
import secrets


app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'

APP_ID  = 1
API_KEY = 'xrcyz2AaN1s9OscnpFLup5DVTi3D7WCIGhYnsmjOyCO8HjAH'
API_URL = 'https://api.easy-login.jp'


@app.route('/')
def index():
    return redirect('/demo.html'), 301


@app.route('/chart.html')
def charts():
    return render_template('chart.html',
                           provider_data=[random.randint(200, 1000),
                                          random.randint(200, 1000),
                                          random.randint(200, 1000)],
                           login_data=[random.randint(1000, 2000),
                                       random.randint(200, 1000)])


@app.route('/pay.html')
def amazon_pay():
    return render_template('pay.html')


@app.route('/app/setting', methods=['POST'])
def app_setting():
    session['api_url'] = request.form.get('api_url')
    session['app_id'] = request.form.get('app_id')
    session['api_key'] = request.form.get('api_key')
    return redirect('/demo.html')


@app.route('/user/<action>', methods=['POST'])
def link_user(action):
    if action not in ['link', 'unlink']:
        abort(400, 'Invalid action')

    user_id = request.form['user_id']
    social_id = request.form['social_id']
    r = requests.put(url='{}/{}/users/{}'.format(session['api_url'], session['app_id'], action),
                     verify=False,
                     json={'user_id': user_id, 'social_id': social_id},
                     headers={'X-Api-Key': session['api_key']})
    msg = str(r.json())
    return redirect('/demo.html?{}_result={}'.format(action, msg))

    
@app.route('/auth/callback')
def auth_callback():
    try:
        token = request.args['token']
        provider = request.args['provider']
        r = requests.get(url='{}/{}/profiles/authorized'.format(session['api_url'], session['app_id']),
                         verify=False,
                         params={'api_key': session['api_key'], 'token': token})
        if r.status_code == 200:
            session[provider] = json.dumps(r.json(), sort_keys=True, indent=2)
        return render_template('result.html', provider=provider.upper(), token=token,
                               profile=json.dumps(r.json(), sort_keys=True, indent=2))
    except KeyError:
        return _handle_error()


@app.route('/auth/failed')
def auth_failed():
    return _handle_error()


@app.route('/demo.html')
def demo_page():
    if 'api_url' not in session:
        session['api_url'] = API_URL
    if 'app_id' not in session:
        session['app_id'] = APP_ID
    if 'api_key' not in session:
        session['api_key'] = API_KEY
    demo_url = request.environ.get('HTTP_X_FORWARDED_PROTO', 'http') + '://' + request.host
    return render_template('demo.html', demo_url=urlparse.quote(demo_url),
                           api_url=session['api_url'],
                           app_id=session['app_id'],
                           api_key=session['api_key'],
                           link_result=request.args.get('link_result', ''),
                           unlink_result=request.args.get('unlink_result', ''),
                           nonce=secrets.token_hex(nbytes=16),
                           line=session.get('line'),
                           amazon=session.get('amazon'),
                           yahoojp=session.get('yahoojp'),
                           facebook=session.get('facebook'),
                           twitter=session.get('twitter'))


@app.route('/logout')
def logout():
    session['line'] = None
    session['amazon'] = None
    session['yahoojp'] = None
    session['facebook'] = None
    session['twitter'] = None
    return redirect('/demo.html')


def _handle_error():
    error = urlparse.unquote(request.args['error'])
    desc = urlparse.unquote(request.args['error_description'])
    provider = request.args['provider']
    return render_template('error.html', error=error, desc=desc, provider=provider)


if __name__ == '__main__':
    import sys
    port = sys.argv[1] if len(sys.argv) > 1 else 8080
    app.run(host='0.0.0.0', port=port, debug=True)
