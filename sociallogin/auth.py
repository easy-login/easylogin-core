import hashlib
from flask import abort, request, jsonify

from sociallogin import app as flask_app, db, login_manager, logger
from sociallogin.backends import get_backend
from sociallogin.models import Apps, AuthLogs, SocialProfiles
from sociallogin.utils import get_remote_ip, base64encode
from sociallogin.exc import TokenParseError


@flask_app.route('/auth/<provider>', defaults={'intent': None})
@flask_app.route('/auth/<provider>/<intent>')
def authorize(provider, intent):
    app_id = request.args.get('app_id')
    callback_uri = request.args.get('callback_uri')
    callback_if_failed = request.args.get('callback_if_failed')
    if not callback_uri or not app_id:
        abort(400, 'Missing or invalid required parameters: app_id, callback_uri')

    backend = get_backend(provider)
    resp = backend.authorize(
        app_id=app_id,
        intent=intent,
        succ_callback=callback_uri,
        fail_callback=callback_if_failed,
        params=request.args
    )
    db.session.commit()
    return resp


@flask_app.route('/auth/<provider>/callback')
def authorize_callback(provider):
    backend = get_backend(provider)
    state = request.args.get('state')
    if not state:
        abort(400, 'Missing a required parameter: state')

    if not backend.verify_callback_success(request.args):
        backend.handle_authorize_error(state=state, params=request.args)

    resp = backend.handle_authorize_success(state=state, params=request.args)
    db.session.commit()
    return resp


@flask_app.route('/auth/<provider>/verify-token', methods=['POST'])
def verify_token(provider):
    backend = get_backend(provider)
    state = request.form.get('state')
    if not state or 'access_token' not in request.form:
        abort(400, 'Missing or invalid required parameters: access token, state')

    resp = backend.handle_authorize_success(state=state, params=request.form)
    db.session.commit()
    return resp


@flask_app.route('/auth/profiles/authorized', methods=['POST'])
def get_authorized_profile():
    token = request.form.get('auth_token')
    try:
        log, args = _verify_auth_request(auth_token=token, params=request.form)
        app = Apps.query.filter_by(_id=log.app_id).one_or_none()

        if log.is_login:
            log.status = AuthLogs.STATUS_SUCCEEDED
        elif app.option_enabled(key='reg_page'):
            log.status = AuthLogs.STATUS_WAIT_REGISTER
        else:
            SocialProfiles.activate(profile_id=log.social_id)
            log.status = AuthLogs.STATUS_SUCCEEDED

        profile = SocialProfiles.query.filter_by(_id=log.social_id).first_or_404()
        body = profile.as_dict(fetch_user=True)
        db.session.commit()

        logger.debug('Profile authenticated', style='hybrid', **body)
        return jsonify(body)
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, token=token)
        abort(400, 'Invalid auth token')


@flask_app.route('/auth/profiles/activate', methods=['POST'])
def activate_profile():
    token = request.form.get('auth_token')
    try:
        log, args = _verify_auth_request(auth_token=token, params=request.form)
        log.status = AuthLogs.STATUS_SUCCEEDED

        SocialProfiles.activate(profile_id=log.social_id)
        db.session.commit()
        return jsonify({'success': True})
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, token=token)
        abort(400, 'Invalid auth token')


@flask_app.route('/ip')
def get_ip():
    return jsonify({'ip': get_remote_ip(request)})


@login_manager.request_loader
def verify_web_api(req):
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
        logger.debug('API authorization failed. ' + repr(e))
        return None


@login_manager.unauthorized_handler
def unauthorized():
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


def _verify_auth_request(auth_token, params):
    log, args = AuthLogs.parse_auth_token(auth_token=auth_token)
    api_key = params.get('api_key')
    if api_key:
        expected = (db.session.query(Apps.api_key)
                    .filter_by(_id=log.app_id, _deleted=0).scalar())
        if expected != api_key:
            abort(401, 'API key authorization failed')
    else:
        code_challenge = args.get('code_challenge')
        verifier = params.get('code_verifier', '')
        if not _verify_code_verifier(verifier=verifier, challenge=code_challenge):
            logger.warn('code_verifier does not match', verifier=verifier)
            abort(401, 'code_verifier does not match')
    return log, args


def _verify_code_verifier(verifier, challenge):
    return challenge == base64encode(hashlib.sha256(verifier.encode('utf8')), urlsafe=False)


def init_app(app):
    from flask.sessions import SecureCookieSessionInterface

    class CustomSessionInterface(SecureCookieSessionInterface):
        """Prevent creating session from API requests."""

        def save_session(self, *args, **kwargs):
            return

    app.session_interface = CustomSessionInterface()
