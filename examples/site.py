from flask import Flask, request, render_template, redirect, session, abort
import urllib.parse as urlparse
import requests
import json

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'

APP_ID = 3
API_KEY = 'api_key'
HOST = 'http://localhost:8080'
API_HOST = 'http://localhost:5000'


@app.route('/')
def index():
    return redirect('/demo.html'), 301


@app.route('/chart.html')
def charts():
    return render_template('chart.html', provider_data=[352, 134, 256], login_data=[2351, 506])


@app.route('/setting', methods=['POST'])
def setting():
    session['app_id'] = request.form.get('app_id', APP_ID)
    session['api_key'] = request.form.get('api_key', API_KEY)
    return redirect('/demo.html')


@app.route('/user/<action>', methods=['POST'])
def link_user(action):
    if action not in ['link', 'unlink']:
        abort(400, 'Invalid action')

    user_id = request.form['user_id']
    social_id = request.form['social_id']
    r = requests.put(url='http://localhost:5000/{}/users/{}'.format(session['app_id'], action),
                     json={'user_id': user_id, 'social_id': social_id},
                     headers={'X-Api-Key': session['api_key']})
    msg = str(r.json())
    return redirect('/demo.html?{}_result={}'.format(action, msg))

    
@app.route('/auth/callback')
def auth_callback():
    try:
        token = request.args['token']
        provider = request.args['provider']
        r = requests.get(url='http://localhost:5000/{}/profiles/authorized'.format(session['app_id']),
                         params={'api_key': session['api_key'], 'token': token})
        if r.status_code == 200:
            session[provider] = json.dumps(r.json(), sort_keys=True, indent=2)
        return render_template('result.html', provider=provider, token=token,
                               profile=json.dumps(r.json(), sort_keys=True, indent=2))
    except KeyError:
        return _handle_error()


@app.route('/auth/failed')
def auth_failed():
    return _handle_error()


@app.route('/demo.html')
def demo_page():
    if 'app_id' not in session:
        session['app_id'] = APP_ID
    if 'api_key' not in session:
        session['api_key'] = API_KEY
    return render_template('demo.html', host=HOST, api_host=API_HOST,
                           app_id=session['app_id'], api_key=session['api_key'],
                           link_result=request.args.get('link_result', ''),
                           unlink_result=request.args.get('unlink_result', ''),
                           line=session.get('line'), amazon=session.get('amazon'), 
                           yahoojp=session.get('yahoojp'))


@app.route('/logout')
def logout():
    session['line'] = None
    session['amazon'] = None
    session['yahoojp'] = None
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
