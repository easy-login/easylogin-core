from passlib.hash import django_pbkdf2_sha256

from sociallogin import db, logger
from sociallogin.exc import TokenParseError, NotFoundError, UnauthorizedError, BadRequestError
from sociallogin.models import SocialProfiles, Admins, Apps
from sociallogin.sec import jwt_token_helper


def admin_authenticate(email, password):
    admin = Admins.query.filter_by(email=email).one_or_none()
    if not admin:
        raise NotFoundError('Email not found')
    if not django_pbkdf2_sha256.verify(secret=password, hash=admin.password):
        raise UnauthorizedError('Invalid authorization credentials')

    admin_attrs = admin.as_dict()
    return {
        'user': admin_attrs,
        'access_token': jwt_token_helper.generate(
            sub=admin._id,
            exp_in_seconds=86400 * 365,
            **admin_attrs,
        )
    }


def admin_info(access_token):
    sub, _ = _validate_access_token(access_token=access_token)
    admin = Admins.query.filter_by(_id=sub).one_or_none()
    if not admin:
        raise NotFoundError('Email not found')
    return {'user': admin.as_dict()}


def convert_social_id(body):
    sub, _ = _validate_access_token(access_token=body['access_token'])
    app_id = body['app_id']
    owner_id = db.session.query(Apps.owner_id).filter_by(_id=app_id).scalar()
    if not owner_id or owner_id != sub:
        raise NotFoundError('App ID not found')

    social_ids = body['ids'].split(',')
    if len(social_ids) > 150:
        raise BadRequestError('Number of IDs cannot be larger than 150')

    scope_ids = SocialProfiles.social_id_to_scope_id(app_id=app_id, social_ids=social_ids)
    return [e[0] for e in scope_ids]


def _validate_access_token(access_token):
    try:
        return jwt_token_helper.decode(token=access_token)
    except TokenParseError as e:
        logger.warning('Parse admin access token failed', error=e.description, token=access_token)
        raise UnauthorizedError('Invalid access token')
