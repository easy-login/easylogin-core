from urllib import parse as up
import json
from flask import abort, redirect, request, url_for, jsonify, make_response

from sociallogin import app as flask_app, db, login_manager, logger, get_remote_ip
from sociallogin.models import Apps, AuthLogs, AssociateLogs, Tokens, Channels
from sociallogin.backends import get_backend
from sociallogin.utils import add_params_to_uri, unix_time_millis
from sociallogin.exc import RedirectLoginError, TokenParseError


@flask_app.route('/auth/<provider>', defaults={'intent': None})
@flask_app.route('/auth/<provider>/<intent>')
def authorize(provider, intent):
    app_id = request.args.get('app_id')
    callback_uri = request.args.get('callback_uri')
    callback_if_failed = request.args.get('callback_if_failed')
    if not callback_uri or not app_id:
        abort(400, 'Missing parameters app_id or callback_uri')

    nonce = request.args.get('nonce', '')
    if len(nonce) > 255:
        abort(400, 'Nonce length exceeded limit 255 characters')
    if nonce and not nonce.isalnum():
        abort(400, 'Invalid nonce, only alphanumeric string accepted')

    backend = get_backend(provider)
    authorize_uri = None
    if intent == AuthLogs.INTENT_ASSOCIATE:
        assoc_token = request.args.get('token')
        try:
            log = AssociateLogs.parse_associate_token(assoc_token)
            if log.provider != provider:
                abort(400, 'Invalid target provider, must be {}'.format(log.provider))

            log.status = AssociateLogs.STATUS_AUTHORIZING
            authorize_uri = backend.build_authorize_uri(
                app_id=app_id,
                succ_callback=callback_uri,
                fail_callback=callback_if_failed,
                nonce=nonce,
                intent=intent,
                user_id=log.user_id,
                provider=provider,
                assoc_id=log._id)
        except TokenParseError as e:
            logger.warning('Parse associate token failed',
                           error=e.description, token=assoc_token)
            abort(400, 'Invalid associate token. ' + e.description)
    else:
        authorize_uri = backend.build_authorize_uri(
            app_id=app_id,
            succ_callback=callback_uri,
            fail_callback=callback_if_failed,
            nonce=nonce,
            intent=intent)

    db.session.commit()
    return redirect(authorize_uri)


@flask_app.route('/auth/<provider>/callback')
def authorize_callback(provider):
    backend = get_backend(provider)
    state = request.args.get('state')
    if not state:
        abort(400, 'Missing parameter state')

    if not backend.verify_request_success(request.args):
        backend.handle_authorize_error(state, request.args)

    profile, log, args = backend.handle_authorize_success(state, qs=request.args)
    intent = args.get('intent')
    if intent == AuthLogs.INTENT_ASSOCIATE:
        if args.get('provider') != provider:
            raise RedirectLoginError(
                error='permission_denied',
                msg='Target provider does not match',
                nonce=args.get('nonce'),
                redirect_uri=log.get_failed_callback(),
                provider=provider)
        elif profile.user_id:
            raise RedirectLoginError(
                error='conflict',
                msg='Profile has linked with another user',
                nonce=args.get('nonce'),
                redirect_uri=log.get_failed_callback(),
                provider=provider)
        profile.link_user_by_id(user_id=args.get('user_id'))
    elif intent == AuthLogs.INTENT_LOGIN and not log.is_login:
        raise RedirectLoginError(
            error='invalid_request',
            msg='Social profile does not exist, should register instead',
            nonce=args.get('nonce'),
            redirect_uri=log.get_failed_callback(),
            provider=provider)
    elif intent == AuthLogs.INTENT_REGISTER and log.is_login:
        raise RedirectLoginError(
            error='invalid_request',
            msg='Social profile already existed, should login instead',
            nonce=args.get('nonce'),
            redirect_uri=log.get_failed_callback(),
            provider=provider)

    token = log.generate_auth_token()
    callback_uri = add_params_to_uri(
        uri=log.callback_uri,
        provider=provider,
        token=token,
        nonce=args.get('nonce'),
        profile_uri=url_for('authorized_profile', _external=True,
                            app_id=log.app_id, token=token)
    )

    db.session.commit()
    if provider == 'amazon':
        return _make_response_for_amazon_pay(callback_uri, profile)
    else:
        return redirect(callback_uri)


@flask_app.route('/ip')
def get_ip():
    return jsonify({'ip': get_remote_ip(request)})


@login_manager.request_loader
def verify_app_auth(req):
    try:
        client_api_key = _extract_api_key(req)
        if not client_api_key:
            raise ValueError('Missing authorization credentials')

        app_id = request.view_args['app_id']
        (api_key, ips, ops) = (db.session.query(Apps.api_key, Apps.allowed_ips, Apps.options)
                               .filter_by(_id=app_id, _deleted=0).one_or_none())
        if client_api_key != api_key:
            raise ValueError('API key does not match')
        if ips:
            allowed_ips = ips.split('|')
            remote_ip = get_remote_ip(req)
            if remote_ip not in allowed_ips and remote_ip != '127.0.0.1':
                logger.info('IP is not allowed', ip=remote_ip, whitelist=allowed_ips)
                raise PermissionError()

        app = Apps()
        app._id = app_id
        app.is_authenticated = True
        app.options = ops
        return app
    except PermissionError:
        abort(403, 'Your IP is not allowed to access this API')
    except Exception as e:
        logger.warning('API authorization failed. ' + repr(e))
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


def _make_response_for_amazon_pay(redirect_uri, profile):
    token = Tokens.find_latest_by_social_id(social_id=profile._id)
    channel = Channels.query.filter_by(app_id=profile.app_id,
                                       provider='amazon').one_or_none()
    cookie_object = {
        "access_token": token.access_token,
        "max_age": 3300,
        "expiration_date": unix_time_millis(token.expires_at),
        "client_id": channel.client_id,
        "scope": channel.get_perms_as_oauth_scope(lpwa=True)
    }
    resp = make_response(redirect(redirect_uri))
    resp.set_cookie(key='amazon_Login_state_cache',
                    value=up.quote(json.dumps(cookie_object), safe=''),
                    expires=None, max_age=3300)
    return resp


def init_app(app):
    from flask.sessions import SecureCookieSessionInterface

    class CustomSessionInterface(SecureCookieSessionInterface):
        """Prevent creating session from API requests."""

        def save_session(self, *args, **kwargs):
            return

    app.session_interface = CustomSessionInterface()
