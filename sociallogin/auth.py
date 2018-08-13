from flask import request, jsonify, redirect, url_for, abort
import hashlib
import jwt
import time
import urllib.parse as urlparse

from sociallogin import app, db
from sociallogin.providers import get_auth_handler


@app.route('/auth/<provider>')
def authenticate(provider):
    site_id = request.args.get('site_id')
    if not site_id:
        abort(404, 'Missing parameter site_id')

    callback_uri = request.args.get('callback_uri')
    if not callback_uri:
        abort(400, 'Missing parameter callback_uri')

    auth_handler = get_auth_handler(provider)
    authorize_uri = auth_handler.build_authorize_uri(site_id, callback_uri)

    return redirect(authorize_uri)


@app.route('/authorize/<provider>/approval_state')
def authorize_callback(provider):
    auth_handler = get_auth_handler(provider)

    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        abort(400, 'Invalid code or state')

    user_id, callback_uri = auth_handler.handle_authorize_response(code, state)
    now = int(time.time())
    token = jwt.encode({
        'iss': app.config['SERVER_NAME'],
        'sub': user_id,
        'exp': now + 600,
        'iat': now
    }, app.config['JWT_SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM']).decode('utf8')

    pr = urlparse.urlparse(callback_uri)
    callback_uri += ('?' if not pr.query else '&') + 'token=' + token
    return redirect(callback_uri)
