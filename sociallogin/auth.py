from flask import abort, redirect, request, url_for, jsonify

from sociallogin import app as flask_app, db, login_manager, logger
from sociallogin.models import Apps, AuthLogs, AssociateLogs
from sociallogin.backends import get_backend
from sociallogin.utils import add_params_to_uri, get_remote_ip
from sociallogin.exc import RedirectLoginError


@flask_app.route('/authorize/<provider>', defaults={'intent': None})
@flask_app.route('/authorize/<provider>/<intent>')
def authorize(provider, intent):
    app_id = request.args.get('app_id')
    callback_uri = request.args.get('callback_uri')
    callback_if_failed = request.args.get('callback_if_failed')
    if not callback_uri or not app_id:
        abort(400, 'Missing parameters app_id or callback_uri')

    backend = get_backend(provider)
    if intent == AuthLogs.INTENT_ASSOCIATE:
        assoc_token = request.args.get('token')
        log = AssociateLogs.parse_from_associate_token(assoc_token)
        log.status = AssociateLogs.STATUS_AUTHORIZING
        authorize_uri = backend.build_authorize_uri(
            app_id=app_id,
            succ_callback=callback_uri,
            fail_callback=callback_if_failed,
            intent=intent,
            user_id=log.user_id,
            provider=provider,
            assoc_id=log._id)
    else:
        authorize_uri = backend.build_authorize_uri(
            app_id=app_id,
            succ_callback=callback_uri,
            fail_callback=callback_if_failed,
            intent=intent)

    db.session.commit()
    return redirect(authorize_uri)


@flask_app.route('/authorize/<provider>/approval_state')
def authorize_callback(provider):
    backend = get_backend(provider)
    state = request.args.get('state')
    if not state:
        abort(400, 'Missing parameter state')

    code = request.args.get('code')
    if not code:
        error = request.args.get('error')
        desc = request.args.get('error_description')
        callback_uri = backend.handle_authorize_error(state, error, desc)
    else:
        profile, log, args = backend.handle_authorize_success(state, code)
        intent = args.get('intent')
        if intent == AuthLogs.INTENT_ASSOCIATE:
            if args.get('provider') != provider:
                raise RedirectLoginError(
                    error='permission_denied',
                    msg='Target provider does not match',
                    redirect_uri=log.safe_get_failed_callback(),
                    provider=provider)
            elif profile.user_id:
                raise RedirectLoginError(
                    error='conflict',
                    msg='Target social profile already linked with another user',
                    redirect_uri=log.safe_get_failed_callback(),
                    provider=provider)
            profile.link_user_by_id(user_id=args.get('user_id'))
        elif intent == AuthLogs.INTENT_LOGIN and not log.is_login:
            raise RedirectLoginError(
                error='invalid_request',
                msg='Social profile does not exist, should register instead',
                redirect_uri=log.safe_get_failed_callback(),
                provider=provider)
        elif intent == AuthLogs.INTENT_REGISTER and log.is_login:
            raise RedirectLoginError(
                error='invalid_request',
                msg='Social profile already existed, should login instead',
                redirect_uri=log.safe_get_failed_callback(),
                provider=provider)

        callback_uri = add_params_to_uri(
            uri=log.callback_uri,
            provider=provider,
            token=log.auth_token,
            profile_uri=url_for('authorized_profile', _external=True,
                                app_id=log.app_id, token=log.auth_token)
        )

    db.session.commit()
    return redirect(callback_uri)


@flask_app.route('/ip')
def get_ip():
    return jsonify({'ip': get_remote_ip(request)})


@login_manager.request_loader
def verify_app_auth(req):
    try:
        api_key = _extract_api_key(req)
        if not api_key:
            abort(401, 'Missing authorization credentials')

        app_id = request.view_args['app_id']
        (_api_key, ips) = (db.session.query(Apps.api_key, Apps.allowed_ips)
                           .filter_by(_id=app_id).one_or_none())
        if api_key != _api_key:
            raise ValueError('API key does not match')
        if ips:
            allowed_ips = ips.split('|')
            remote_ip = get_remote_ip(req)
            if remote_ip not in allowed_ips and remote_ip != '127.0.0.1':
                raise PermissionError('IP {} is not allowed'.format(remote_ip))

        app = Apps()
        app._id = app_id
        app.is_authenticated = True
        return app
    except PermissionError as e:
        logger.error(repr(e))
        abort(403, 'Your IP is not allowed to access this API')
    except Exception as e:
        logger.error(repr(e))
        abort(401, 'Wrong credentials, could not verify your API key')


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
