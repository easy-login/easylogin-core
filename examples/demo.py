from flask import Flask, request, jsonify, redirect, url_for, abort
import base64
import hashlib
import uuid
import requests

app = Flask(__name__)

API_KEY = 'YjMxZDExYTU1NjQyOTIwNzc3MWE3OWY5NDJhYWVjOThkZThjYmYxMA=='

providers = {
    'facebook': {
        'app_id': '929981633775605',
        'app_secret': 'c3f3139b83d7cba8fdd3e935da15ca81',
        'redirect_uri': 'http://localhost:5000/authorize/facebook'
    },
    'amazon': {
        'client_id': 'amzn1.application-oa2-client.e4f978fd4ef347ddbf8206d16f0df5eb',
        'client_secret': 'ad90102af6bb3de8bd0338bba92000ff427f7a47467460b49aa0a0c0ef2a8592',
        'redirect_uri': 'http://localhost:5000/authorize/amazon',
        'authorize_uri': '''
            https://www.amazon.com/ap/oa?client_id={client_id}
            &scope=profile
            &response_type=code
            &state={state}
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token'
    }
}

db = {}


def b64encode_string(s, urlsafe=False, charset='utf8'):
    ib = s.encode(charset)
    ob = base64.urlsafe_b64encode(ib) if urlsafe else base64.standard_b64encode(ib) 
    return ob.decode('ascii')


def b64decode_string(s, urlsafe=False, charset='utf8'):
    ib = s.encode('ascii')
    ob = base64.urlsafe_b64decode(ib) if urlsafe else base64.standard_b64decode(ib)
    return ob.decode(charset)


@app.route('/users/<user_id>', methods = ['GET'])
def get_user(user_id):
    if user_id not in db:
        abort(404)
    return jsonify(db[user_id])


@app.route('/login', methods = ['GET'])
def login():
    user_id = request.args['user_id']
    provider = providers[request.args['provider']]

    url = provider['authorize_uri'].format(
        client_id=provider['client_id'],
        redirect_uri=provider['redirect_uri'], 
        state=b64encode_string('user_id={}'.format(user_id)), urlsafe=True)

    return redirect(url)


@app.route('/authorize/amazon', methods = ['GET'])
def authorize_amazon():
    code = request.args.get('code')
    state = request.args.get('state')

    provider = providers['amazon']
    url = provider['token_uri']
    r = requests.post(url, data={
        'code': code,
        'client_secret': provider['client_secret'],
        'client_id': provider['client_id'],
        'redirect_uri': provider['redirect_uri'],
        'grant_type': 'authorization_code'
    })
    print('code', code)
    print('status code', r.status_code)

    user_id = b64decode_string(state, urlsafe=True).split('=')[1]
    plus_id = hashlib.sha1(str(uuid.uuid4()).encode('utf8')).hexdigest()
    db[user_id] = {
        'user_id': user_id,
        'plus_id': plus_id,
        'access_token': r.json()
    }
    return redirect(url_for('get_user', user_id=user_id))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



