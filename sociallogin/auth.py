from flask import abort, redirect, request, jsonify

from sociallogin import app as flask_app, db, login_manager, logger, get_remote_ip
from sociallogin.backends import get_backend
from sociallogin.exc import TokenParseError
from sociallogin.models import Apps, AuthLogs, AssociateLogs
from sociallogin.utils import smart_str2bool, update_dict


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

    sandbox = request.args.get('sandbox')
    backend = get_backend(provider, sandbox=smart_str2bool(sandbox))
    extra = dict()

    if intent == AuthLogs.INTENT_ASSOCIATE:
        assoc_token = request.args.get('associate_token')
        try:
            alog = AssociateLogs.parse_associate_token(assoc_token)
            if alog.provider != provider:
                abort(400, 'Invalid target provider, must be {}'.format(alog.provider))

            alog.status = AssociateLogs.STATUS_AUTHORIZING
            update_dict(extra, dst_social_id=alog.dst_social_id, provider=provider)
        except TokenParseError as e:
            logger.warning('Parse associate token failed',
                           error=e.description, token=assoc_token)
            abort(400, 'Invalid associate token')
    elif intent == AuthLogs.INTENT_PAY_WITH_AMAZON:
        update_dict(extra, lpwa_domain=request.args.get('site_domain'))

    authorize_uri = backend.build_authorize_uri(
        app_id=app_id,
        intent=intent,
        succ_callback=callback_uri,
        fail_callback=callback_if_failed,
        nonce=nonce,
        sandbox=sandbox, **extra)
    db.session.commit()
    return redirect(authorize_uri)


@flask_app.route('/auth/<provider>/callback')
def authorize_callback(provider):
    backend = get_backend(provider)
    state = request.args.get('state')
    if not state:
        abort(400, 'Missing parameter state')

    if not backend.verify_callback_success(request.args):
        backend.handle_authorize_error(state, request.args)

    resp = backend.handle_authorize_success(state=state, qs=request.args)
    db.session.commit()
    return resp


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


def init_app(app):
    from flask.sessions import SecureCookieSessionInterface

    class CustomSessionInterface(SecureCookieSessionInterface):
        """Prevent creating session from API requests."""

        def save_session(self, *args, **kwargs):
            return

    app.session_interface = CustomSessionInterface()
