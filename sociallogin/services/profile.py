from typing import Dict, Any

from sociallogin import db
from sociallogin.backends import is_valid_provider
from sociallogin.exc import BadRequestError, NotFoundError, ConflictError
from sociallogin.models import SocialProfiles, AssociateLogs
from sociallogin.utils import gen_random_token, smart_str2int


def link_user(app_id: str, body: Dict[str, Any]):
    alias = int(body['social_id'])
    if alias <= 0:
        raise BadRequestError('Invalid social_id: ' + str(body.get('social_id')))
    user_pk = body['user_id']

    SocialProfiles.link_with_user(
        app_id=app_id,
        alias=alias, user_pk=user_pk,
        create_if_not_exist=body.get('create_user', 'true') == 'true'
    )
    db.session.commit()


def unlink_user(app_id: str, body: Dict[str, Any]):
    user_pk = body['user_id']
    alias = int(body['social_id'])
    if alias <= 0:
        raise BadRequestError('Invalid social_id: ' + str(body.get('social_id')))

    num_affected = SocialProfiles.unlink_from_user(
        app_id=app_id,
        alias=alias, user_pk=user_pk
    )
    db.session.commit()
    return num_affected


def merge_user(app_id: str, body: Dict[str, Any]):
    src_user_pk = body.get('src_user_id')
    src_alias = smart_str2int(body.get('src_social_id', '0'))
    dst_user_pk = body.get('dst_user_id')
    dst_alias = smart_str2int(body.get('dst_social_id', '0'))

    if not src_user_pk and src_alias <= 0:
        raise BadRequestError('At least one valid parameter src_user_id or src_social_id must be provided')
    if not dst_user_pk and dst_alias <= 0:
        raise BadRequestError('At least one valid parameter dst_user_id or dst_social_id must be provided')

    SocialProfiles.merge_profiles(
        app_id=app_id,
        src_user_pk=src_user_pk, src_alias=src_alias,
        dst_user_pk=dst_user_pk, dst_alias=dst_alias
    )
    db.session.commit()


def disassociate(app_id: str, body: Dict[str, Any]):
    providers = body['providers'].split(',')
    for provider in providers:
        if not is_valid_provider(provider):
            raise BadRequestError('Invalid provider ' + provider)
    user_pk, alias = _parse_and_validate_identifiers(body)

    num_affected = SocialProfiles.disassociate_provider(
        app_id=app_id, providers=providers,
        user_pk=user_pk, alias=alias)

    db.session.commit()
    return num_affected


def get_user(app_id: str, body: Dict[str, Any]):
    user_pk, alias = _parse_and_validate_identifiers(body)
    return SocialProfiles.get_full_profile(
        app_id=app_id,
        user_pk=user_pk, alias=alias,
        pretty=body.get('pretty', 'false') == 'true'
    )


def delete_user(app_id: str, body: Dict[str, Any]):
    user_pk, alias = _parse_and_validate_identifiers(body)
    num_affected = SocialProfiles.delete_profile(
        app_id=app_id,
        alias=alias, user_pk=user_pk)

    db.session.commit()
    return num_affected


def delete_user_info(app_id: str, body: Dict[str, Any]):
    user_pk, alias = _parse_and_validate_identifiers(body)

    num_affected = SocialProfiles.reset_info(
        app_id=app_id,
        alias=alias, user_pk=user_pk)

    db.session.commit()
    return num_affected


def get_associate_token(app_id: str, body: Dict[str, Any]):
    provider = body.get('provider')
    if not is_valid_provider(provider):
        raise BadRequestError('Invalid provider')
    user_pk, alias = _parse_and_validate_identifiers(body)

    profiles = SocialProfiles.find_by_pk(app_id=app_id, user_pk=user_pk)\
        if user_pk else SocialProfiles.query.filter_by(alias=alias).all()
    if not profiles:
        raise NotFoundError('User ID or Social ID not found')

    for p in profiles:
        if provider == p.provider:
            raise ConflictError('User has linked with another social profile for this provider')
    log = AssociateLogs(provider=provider, app_id=app_id,
                        social_id=profiles[0].alias,
                        nonce=gen_random_token(nbytes=16, format='hex'))
    db.session.add(log)
    db.session.flush()

    associate_token = log.generate_associate_token()
    db.session.commit()
    return {
        'token': associate_token,
        'target_provider': provider
    }


def _parse_and_validate_identifiers(params):
    user_pk = params.get('user_id')
    alias = smart_str2int(params.get('social_id', '0'))
    if not user_pk and alias <= 0:
        raise BadRequestError('At least one parameter social_id or user_id must be provided')
    return user_pk, alias
