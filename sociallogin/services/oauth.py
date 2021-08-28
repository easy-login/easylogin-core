import hashlib
from typing import Dict, Any

from flask import abort

from sociallogin import db, logger
from sociallogin.backends import get_backend
from sociallogin.backends.utils import parse_auth_token
from sociallogin.entities import OAuthAuthorizeParams, OAuthCallbackParams
from sociallogin.models import Apps, AuthLogs, SocialProfiles


def authorize(params: OAuthAuthorizeParams):
    backend = get_backend(params.provider)
    resp = backend.authorize(params)
    db.session.commit()
    return resp


def web_authorize_callback(params: OAuthCallbackParams):
    backend = get_backend(params.provider)

    is_success = False
    if backend.OAUTH_VERSION == 2:
        is_success = bool(params.code)
    elif backend.OAUTH_VERSION == 1:
        is_success = params.oauth_token and params.oauth_verifier

    if is_success:
        resp = backend.handle_authorize_error(params)
    else:
        resp = backend.handle_authorize_success(params)
    db.session.commit()
    return resp


def mobile_authorize_callback(params: OAuthCallbackParams):
    backend = get_backend(params.provider)
    resp = backend.handle_authorize_success(params)
    db.session.commit()
    return resp


def get_authorized_profile(auth_token: str, params: Dict[str, Any]) -> Dict[str, Any]:
    log, args = _verify_auth_request(auth_token=auth_token, params=params)
    app = Apps.query.filter_by(_id=log.app_id).one_or_none()

    if log.is_login:
        log.status = AuthLogs.STATUS_SUCCEEDED
    elif app.option_enabled(key='reg_page'):
        log.status = AuthLogs.STATUS_WAIT_REGISTER
    else:
        SocialProfiles.activate(profile_id=log.social_id)
        log.status = AuthLogs.STATUS_SUCCEEDED

    profile = SocialProfiles.query.filter_by(_id=log.social_id).first_or_404()
    # TODO: What is fetch_user=True
    body = profile.as_dict(fetch_user=True)
    db.session.commit()

    return body


def activate_profile(auth_token: str, params: Dict[str, Any]):
    log, args = _verify_auth_request(auth_token=auth_token, params=params)
    log.status = AuthLogs.STATUS_SUCCEEDED

    SocialProfiles.activate(profile_id=log.social_id)
    db.session.commit()


def _verify_auth_request(auth_token, params):
    log, args = parse_auth_token(auth_token=auth_token)
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
    return challenge == hashlib.sha256(verifier.encode('utf8')).hexdigest()
