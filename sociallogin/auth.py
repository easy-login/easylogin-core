from flask import request, jsonify, redirect, url_for, abort
import urllib.parse as urlparse

from sociallogin import app, db, login_manager
from sociallogin.models import Sites
from sociallogin.providers import get_auth_handler
from sociallogin import utils


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
    token = utils.gen_jwt_token(sub=user_id, exp_in_seconds=300)

    pr = urlparse.urlparse(callback_uri)
    callback_uri += ('?' if not pr.query else '&') + 'token=' + token
    
    return redirect(callback_uri)


@login_manager.request_loader
def verify_site_auth(req):
    api_key = _extract_api_key(req)
    if not api_key:
        abort(401, 'Unauthorized. Missing authorization parameters')

    site = Sites.query.filter_by(api_key=api_key).one_or_none()
    if not site:
        abort(403, 'Wrong credentials. Could not verify your api_key')
    site.is_authenticated = True
    return site


def _extract_api_key(req):
    if req.method == 'GET':
        api_key = req.args.get('api_key')
        if api_key:
            return api_key
    api_key = req.headers.get('X-Api-Key')
    if api_key:
        return api_key

    authorization = req.headers.get('Authorization')
    if authorization:
        api_key = authorization.replace('ApiKey ', '', 1)
