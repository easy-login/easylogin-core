from flask import abort, jsonify, request
from flask_login import login_required, current_user as app

from sociallogin import app as flask_app, db, logger
from sociallogin.models import SocialProfiles, AuthLogs, AssociateLogs
from sociallogin.utils import gen_random_token, smart_str2int
from sociallogin.backends import is_valid_provider
from sociallogin.exc import TokenParseError


@flask_app.route('/<int:app_id>/profiles/authorized', methods=['POST'])
def authorized_profile(app_id):
    token = request.json.get('token')
    try:
        log = AuthLogs.parse_auth_token(auth_token=token)
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


@flask_app.route('/<int:app_id>/profiles/activate', methods=['POST'])
def activate(app_id):
    token = request.json.get('token')
    try:
        log = AuthLogs.parse_auth_token(auth_token=token)
        log.status = AuthLogs.STATUS_SUCCEEDED
        SocialProfiles.activate(profile_id=log.social_id)
        db.session.commit()
        return jsonify({'success': True})
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, token=token)
        abort(400, 'Invalid auth token')


@flask_app.route('/<int:app_id>/users/link', methods=['PUT'])
@login_required
def link_user(app_id):
    body = request.json
    alias = int(body['social_id'])
    user_pk = body['user_id']
    if alias <= 0:
        abort(404, 'Social ID not found')

    SocialProfiles.link_with_user(
        app_id=app_id,
        alias=alias, user_pk=user_pk,
        create_if_not_exist=body.get('create_user', True)
    )
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/unlink', methods=['PUT'])
@login_required
def unlink_user(app_id):
    body = request.json
    user_pk = body['user_id']
    alias = int(body['social_id'])
    if alias <= 0:
        abort(404, 'Social ID not found')

    num_affected = SocialProfiles.unlink_from_user(
        app_id=app_id,
        alias=alias, user_pk=user_pk
    )
    if not num_affected:
        abort(404, 'Social ID not found or not linked with any users')
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/merge', methods=['PUT'])
@login_required
def merge_user(app_id):
    body = request.json
    src_user_pk = body.get('src_user_id')
    src_alias = smart_str2int(body.get('src_social_id', '0'))
    dst_user_pk = body.get('dst_user_id')
    dst_alias = smart_str2int(body.get('dst_social_id', '0'))

    if not src_user_pk and src_alias <= 0:
        abort(400, 'At least one parameter src_user_id or src_social_id must be provided')
    if not dst_user_pk and dst_alias <= 0:
        abort(400, 'At least one parameter dst_user_id or dst_social_id must be provided')

    SocialProfiles.merge_profiles(
        app_id=app_id,
        src_user_pk=src_user_pk, src_alias=src_alias,
        dst_user_pk=dst_user_pk, dst_alias=dst_alias
    )
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/disassociate', methods=['PUT'])
@login_required
def disassociate(app_id):
    body = request.json
    providers = body['providers'].split(',')
    for provider in providers:
        if not is_valid_provider(provider):
            abort(400, 'Invalid provider ' + provider)
    user_pk, alias = _parse_and_validate_identifiers(request.args)

    num_affected = SocialProfiles.disassociate_provider(
        app_id=app_id, providers=providers,
        user_pk=user_pk, alias=alias)
    if not num_affected:
        abort(404, 'User ID or Social ID not found')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users')
@login_required
def get_user(app_id):
    user_pk, alias = _parse_and_validate_identifiers(request.args)
    return jsonify(SocialProfiles.get_full_profile(
        app_id=app_id,
        user_pk=user_pk, alias=alias
    ))


@flask_app.route('/<int:app_id>/users', methods=['DELETE'])
@login_required
def delete_user(app_id):
    body = request.json
    user_pk, alias = _parse_and_validate_identifiers(body)

    num_affected = SocialProfiles.delete_profile(
        app_id=app_id,
        alias=alias, user_pk=user_pk)
    if not num_affected:
        abort(404, 'User ID or Social ID not found')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/delete_info', methods=['PUT'])
def delete_user_info(app_id):
    body = request.json
    user_pk, alias = _parse_and_validate_identifiers(body)

    num_affected = SocialProfiles.reset_info(
        app_id=app_id,
        alias=alias, user_pk=user_pk)
    if not num_affected:
        abort(404, 'User ID or Social ID not found')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/associate_token')
@login_required
def get_associate_token(app_id):
    provider = request.args['provider']
    if not is_valid_provider(provider):
        abort(400, 'Invalid provider')
    user_pk, alias = _parse_and_validate_identifiers(request.args)

    profiles = SocialProfiles.find_by_pk(app_id=app_id, user_pk=user_pk)\
        if user_pk else SocialProfiles.query.filter_by(alias=alias).all()
    if not profiles:
        abort(404, 'User ID or Social ID not found')

    for p in profiles:
        if provider == p.provider:
            abort(409, 'User has linked with another social profile for this provider')
    log = AssociateLogs(provider=provider, app_id=app_id,
                        social_id=profiles[0].alias,
                        nonce=gen_random_token(nbytes=16, format='hex'))
    db.session.add(log)
    db.session.flush()

    associate_token = log.generate_associate_token()
    db.session.commit()
    return jsonify({
        'token': associate_token,
        'target_provider': provider
    })


def _parse_and_validate_identifiers(params):
    user_pk = params.get('user_id')
    alias = smart_str2int(params.get('social_id', '0'))
    if not user_pk and alias <= 0:
        abort(400, 'At least one parameter social_id or user_id must be provided')
    return user_pk, alias
