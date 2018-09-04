from flask import Flask, request, render_template
import urllib.parse as urlparse
import requests
import json

app = Flask(__name__, template_folder='.')


@app.route('/auth/callback')
def auth_callback():
    try:
        token = request.args['token']
        provider = request.args['provider']
        r = requests.get(url='http://localhost:5000/profiles/authorized',
                         params={'api_key': 'passw0rdTec', 'token': token})
        return render_template('demo.html', provider=provider, token=token,
                               profile=json.dumps(r.json(), sort_keys=True, indent=2))
    except KeyError:
        error = urlparse.unquote(request.args['error'])
        desc = urlparse.unquote(request.args['error_description'])
        provider = request.args['provider']
        return render_template('error.html', error=error, desc=desc, provider=provider)


@app.route('/auth/failed')
def auth_failed():
    error = urlparse.unquote(request.args['error'])
    desc = urlparse.unquote(request.args['error_description'])
    provider = request.args['provider']
    return render_template('error.html', error=error, desc=desc, provider=provider)


@app.route('/demo.html')
def demo_page():
    return render_template('demo.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
