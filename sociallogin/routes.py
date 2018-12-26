from flask import abort, jsonify, request, url_for
from flask_login import login_required, current_user as app
from sqlalchemy import func, and_

from sociallogin import app as flask_app, db, logger
from sociallogin.models import SocialProfiles, Users, AuthLogs, AssociateLogs
from sociallogin.utils import gen_random_token
from sociallogin.backends import is_valid_provider
from sociallogin.exc import TokenParseError, ConflictError


@flask_app.route('/<int:app_id>/profiles/authorized', methods=['POST'])
@login_required
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
        body = profile.as_dict()
        db.session.commit()

        logger.debug('Profile authenticated', style='hybrid', **body)
        return jsonify(body)
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, token=token)
        abort(400, 'Invalid auth token. ' + e.description)


@flask_app.route('/<int:app_id>/profiles/activate', methods=['POST'])
@login_required
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
        abort(400, 'Invalid auth token. ' + e.description)


@flask_app.route('/<int:app_id>/users/link', methods=['PUT'])
@login_required
def link_user(app_id):
    body = request.json
    social_id = int(body['social_id'])
    user_pk = body['user_id']
    if social_id <= 0:
        abort(404, 'Social ID not found')

    SocialProfiles.link_user_by_pk(
        app_id=app_id,
        social_id=social_id, user_pk=user_pk,
        create_if_not_exist=body.get('create_user', True)
    )
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/unlink', methods=['PUT'])
@login_required
def unlink_user(app_id):
    body = request.json
    user_pk = body['user_id']
    social_id = int(body['social_id'])
    if social_id <= 0:
        abort(404, 'Social ID not found')

    num_affected = SocialProfiles.unlink_user_by_pk(
        app_id=app_id,
        social_id=social_id, user_pk=user_pk
    )
    if not num_affected:
        abort(404, 'Social ID not found or not linked with any users')
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/merge', methods=['PUT', 'GET'])
# @login_required
def merge_user(app_id):
    # body = request.json
    # src_social_id = int(body['src_social_id'])
    # dst_user_pk = body.get('dst_user_id')
    # dst_social_id = int(body.get('dst_social_id', '0'))
    # if src_social_id <= 0:
    #     abort(404, 'Source Social ID not found')

    raise ConflictError('Test error', data={
        'source_providers': ['line', 'yahoojp'],
        'destination_providers': ['line', 'amazon']
    })


@flask_app.route('/<int:app_id>/users/disassociate', methods=['PUT'])
@login_required
def disassociate(app_id):
    body = request.json
    providers = body['providers'].split(',')
    for provider in providers:
        if not is_valid_provider(provider):
            abort(400, 'Invalid provider ' + provider)
    user_pk = body.get('user_id')
    social_id = int(body.get('social_id', '0'))

    if user_pk:
        num_affected = SocialProfiles.disassociate_by_pk(
            app_id=app_id, user_pk=user_pk,
            providers=providers)
        if not num_affected:
            abort(404, 'User ID not found')
    elif social_id > 0:
        num_affected = SocialProfiles.disassociate_by_id(
            app_id=app_id, social_id=social_id,
            providers=providers)
        if not num_affected:
            abort(404, 'Social ID not found')
    else:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users')
@login_required
def get_user(app_id):
    user_pk = request.args.get('user_id')
    social_id = int(request.args.get('social_id', '0'))
    if not user_pk and social_id <= 0:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    return jsonify(SocialProfiles.get_full_profile(
        app_id=app_id,
        user_pk=user_pk,
        social_id=social_id
    ))


@flask_app.route('/<int:app_id>/users', methods=['DELETE'])
@login_required
def delete_user(app_id):
    body = request.json
    user_pk = body.get('user_id')
    social_id = int(body.get('social_id', '0'))

    if user_pk:
        SocialProfiles.delete_by_user_pk(app_id=app_id, user_pk=user_pk)
    elif social_id > 0:
        SocialProfiles.delete_by_alias(app_id=app_id, alias=social_id)
    else:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/reset', methods=['PUT'])
def reset_user_info(app_id):
    body = request.json
    user_pk = body.get('user_id')
    social_id = int(body.get('social_id', '0'))
    if not user_pk and social_id <= 0:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    num_affected = SocialProfiles.reset_info(
        app_id=app_id,
        social_id=social_id, user_pk=user_pk)
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
    user_pk = request.args.get('user_id')
    social_id = int(request.args.get('social_id', '0'))
    if not user_pk and social_id <= 0:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    profiles = SocialProfiles.find_by_pk(app_id=app_id, user_pk=user_pk)\
        if user_pk else SocialProfiles.query.filter_by(alias=social_id).all()
    if not profiles:
        abort(404, 'User ID or Social ID not found')

    for p in profiles:
        if provider == p.provider:
            abort(409, 'User has linked with another social profile for this provider')
    log = AssociateLogs(provider=provider, app_id=app_id,
                        social_id=profiles[0].alias,
                        nonce=gen_random_token(nbytes=32))
    db.session.add(log)
    db.session.flush()

    associate_token = log.generate_associate_token()
    db.session.commit()
    return jsonify({
        'token': associate_token,
        'target_provider': provider
    })
