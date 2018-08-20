from flask import request, jsonify, redirect, url_for, abort
import urllib.parse as urlparse
from flask_login import login_required

from sociallogin import app, db, login_manager
from sociallogin.models import Apps, AuthLogs, Users
from sociallogin.providers import get_auth_handler
from sociallogin import utils


@app.route('/auth/<provider>')
def authenticate(provider):
    site_id = request.args.get('site_id')
    callback_uri = request.args.get('callback_uri')
    if not callback_uri or not site_id:
        abort(400, 'Missing parameters site_id or callback_uri')

    auth_handler = get_auth_handler(provider)
    authorize_uri = auth_handler.build_authorize_uri(site_id, callback_uri)

    return redirect(authorize_uri)


@app.route('/authorize/<provider>/approval_state')
def authorize_callback(provider):
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        abort(400, 'Missing parameters code or state')

    auth_handler = get_auth_handler(provider)
    _, once_token, callback_uri = auth_handler.handle_authorize_response(code, state)

    pr = urlparse.urlparse(callback_uri)
    query = urlparse.urlencode({'provider': provider, 'token': once_token})
    callback_uri += ('?' if not pr.query else '&') + query
    
    return redirect(callback_uri)


@app.route('/users/authenticated')
@login_required
def authenticated_user():
    token = request.args.get('token')
    if not token:
        abort(400, 'Missing parameter token') 
    log = Logs.find_by_once_token(once_token=token)
    user_id = log.user_id
    return jsonify(Users.query.filter_by(_id=user_id).as_map())


@login_manager.request_loader
def verify_app_auth(req):
    api_key = _extract_api_key(req)
    if not api_key:
        abort(401, 'Unauthorized. Missing authorization parameters')
    try:
        (_id, allowed_ips) = (db.session.query(Apps._id, Apps.allowed_ips)
                            .filter_by(api_key=api_key).one_or_none())
        app = Apps()
        app._id = _id
        app.allowed_ips = allowed_ips
        app.is_authenticated = True
        return app
    except:
        abort(403, 'Wrong credentials. Could not verify your api_key')


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


def init_app(app):
    from flask.sessions import SecureCookieSessionInterface

    class CustomSessionInterface(SecureCookieSessionInterface):
        """Prevent creating session from API requests."""
        def save_session(self, *args, **kwargs):
            return
    app.session_interface = CustomSessionInterface()
