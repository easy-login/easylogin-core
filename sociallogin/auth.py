import urllib.parse as urlparse
from flask import abort, redirect, request

from sociallogin import app as flask_app, db, login_manager
from sociallogin.models import Apps
from sociallogin.providers import get_auth_handler
from sociallogin.utils import add_params_to_uri


@flask_app.route('/authenticate/<provider>')
def authenticate(provider):
    app_id = request.args.get('app_id')
    callback_uri = request.args.get('callback_uri')
    callback_if_failed = request.args.get('callback_if_failed')
    if not callback_uri or not app_id:
        abort(400, 'Missing parameters app_id or callback_uri')

    auth_handler = get_auth_handler(provider)
    authorize_uri = auth_handler.build_authorize_uri(app_id, callback_uri, callback_if_failed)

    return redirect(authorize_uri)


@flask_app.route('/authorize/<provider>/approval_state')
def authorize_callback(provider):
    auth_handler = get_auth_handler(provider)
    state = request.args.get('state')
    if not state:
        abort(400, 'Missing parameter state')

    code = request.args.get('code')
    if not code:
        error = request.args.get('error')
        desc = request.args.get('error_description')
        fail_callback = auth_handler.handle_authorize_error(state, error, desc)
        redirect_uri = add_params_to_uri(fail_callback, {
            'error': error, 
            'error_description': desc,
            'provider': provider
        })
        return redirect(redirect_uri)
    else:
        _, once_token, succ_callback = auth_handler.handle_authorize_response(code, state)
        callback_uri = add_params_to_uri(succ_callback, {
            'token': once_token,
            'provider': provider 
        })
        return redirect(callback_uri)


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
        return api_key


def init_app(app):
    from flask.sessions import SecureCookieSessionInterface

    class CustomSessionInterface(SecureCookieSessionInterface):
        """Prevent creating session from API requests."""
        def save_session(self, *args, **kwargs):
            return
    app.session_interface = CustomSessionInterface()
