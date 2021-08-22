import urllib.parse as up
from typing import Tuple, Dict, Any, Optional

from sociallogin import logger
from sociallogin.exc import BadRequestError
from sociallogin.models import AuthLogs, AssociateLogs
from sociallogin.sec import jwt_token_service as jwt_token_svc, easy_token_service as easy_token_svc


def parse_auth_token(auth_token: str) -> Tuple[AuthLogs, Dict[str, Any]]:
    log_id, args = easy_token_svc.decode(token=auth_token)
    log: Optional[AuthLogs] = AuthLogs.query.filter_by(_id=log_id).one_or_none()

    if not log or log.nonce != args.get('_nonce'):
        logger.debug('Invalid auth token or nonce does not match')
        raise BadRequestError('Invalid auth token')

    if log.status not in [AuthLogs.STATUS_AUTHORIZED, AuthLogs.STATUS_WAIT_REGISTER]:
        logger.debug('Validate auth token failed. Illegal auth log status.',
                     status=log.status,
                     expected=[AuthLogs.STATUS_AUTHORIZED, AuthLogs.STATUS_WAIT_REGISTER])
        raise BadRequestError('Invalid auth token')

    return log, args


def parse_associate_token(associate_token: str):
    social_id, args = easy_token_svc.decode(token=associate_token)
    log: Optional[AssociateLogs] = AssociateLogs.query \
        .filter_by(dst_social_id=social_id) \
        .order_by(AssociateLogs._id.desc()).first()

    if not log or log.nonce != args.get('_nonce'):
        logger.debug('Invalid associate token or nonce does not match')
        raise BadRequestError('Invalid associate token')

    if log.status != AssociateLogs.STATUS_NEW:
        logger.debug('Illegal associate log status', status=log.status, expected=AssociateLogs.STATUS_NEW)
        raise BadRequestError('Invalid associate token')

    return log


def generate_oauth_state(log: AuthLogs, **kwargs) -> str:
    return jwt_token_svc.generate(sub=log._id, exp_in_seconds=3600, aud=log.app_id,
                                  _nonce=log.nonce, **kwargs)


def generate_auth_token(log: AuthLogs, **kwargs) -> str:
    return easy_token_svc.generate(sub=log._id, exp_in_seconds=3600,
                                   _type='auth', _nonce=log.nonce, **kwargs)


def generate_associate_token(log: AssociateLogs, **kwargs):
    return easy_token_svc.generate(sub=log.dst_social_id, exp_in_seconds=600,
                                   _type='associate', _nonce=log.nonce, **kwargs)


def verify_callback_uri(allowed_uris, uri):
    if not uri:
        return False
    r1 = up.urlparse(uri)
    # Always allow callback for hosted JS
    if r1.netloc == 'api.easy-login.jp' \
            and r1.path == '/hosted/auth/callback' \
            and r1.scheme == 'https':
        return True

    for _uri in allowed_uris:
        r2 = up.urlparse(_uri)
        ok = r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path
        if ok:
            return True
    return False