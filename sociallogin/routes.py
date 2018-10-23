from flask import abort, jsonify, request, url_for
from flask_login import login_required, current_user as current_app
from sqlalchemy import func, and_

from sociallogin import app as flask_app, db, logger
from sociallogin.models import SocialProfiles, Users, AuthLogs, AssociateLogs
from sociallogin.utils import gen_random_token
from sociallogin.backends import is_valid_provider


@flask_app.route('/<int:app_id>/profiles/authorized')
@login_required
def authorized_profile(app_id):
    token = request.args.get('token')
    if not token:
        abort(400, 'Missing parameter token')
    log = AuthLogs.find_by_one_time_token(auth_token=token)
    try:
        log.status = AuthLogs.STATUS_SUCCEEDED
        profile = SocialProfiles.query.filter_by(_id=log.social_id).first_or_404()
        logger.debug('Authorized profile: \n' + repr(profile))
        body = profile.as_dict()
        return jsonify(body)
    except Exception as e:
        logger.error(repr(e))
        log.status = AuthLogs.STATUS_FAILED
        raise
    finally:
        db.session.commit()


@flask_app.route('/<int:app_id>/users/link', methods=['PUT'])
@login_required
def link_user(app_id):
    body = request.json
    social_id = int(body['social_id'])
    user_pk = body['user_id']
    if social_id <= 0:
        abort(404, 'Social ID not found')

    profile = SocialProfiles.query.filter_by(alias=social_id).first()
    if not profile:
        abort(404, 'Social ID not found')
    if profile.user_id:
        abort(409, 'Social profile has linked with an exists user')

    profile.link_user_by_pk(user_pk)
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/unlink', methods=['PUT'])
@login_required
def unlink_user(app_id):
    body = request.json
    user_pk = body['user_id']

    if 'social_id' in body:
        social_id = int(body['social_id'])
        if social_id <= 0:
            abort(404, 'Social ID not found')

        profiles = SocialProfiles.query.filter_by(alias=social_id).all()
        if not profiles:
            abort(404, 'Social ID not found')
        for p in profiles:
            if not p.user_id:
                abort(409, "Social profile are not linked with any user")
            p.unlink_user_by_pk(user_pk)
    elif 'providers' in body:
        providers = body['providers'].split(',')
        for provider in providers:
            if not is_valid_provider(provider):
                abort(400, 'Invalid provider')
        SocialProfiles.unlink_by_provider(app_id=app_id, user_pk=user_pk, providers=providers)
    else:
        abort(400, 'At least one valid parameter social_id or providers must be provided')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users')
@login_required
def get_user(app_id):
    args = request.args
    user_pk = args.get('user_id')
    social_id = int(args.get('social_id'))

    if user_pk:
        return jsonify(Users.get_full_as_dict(app_id=app_id, pk=user_pk))
    elif social_id > 0:
        profile = SocialProfiles.query.filter_by(alias=social_id).first()
        if not profile:
            abort(404, 'Social ID not found')
        if profile.user_pk:
            return jsonify(Users.get_full_as_dict(app_id=app_id, pk=profile.user_pk))
        else:
            return jsonify({
                'user': None,
                'profiles': [profile.as_dict()]
            })
    else:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')


@flask_app.route('/<int:app_id>/users', methods=['DELETE'])
@login_required
def delete_user(app_id):
    body = request.json
    user_pk = body.get('user_id')
    social_id = int(body.get('social_id'))

    if user_pk:
        SocialProfiles.delete_by_user_pk(app_id=app_id, user_pk=user_pk)
    elif social_id > 0:
        SocialProfiles.delete_by_alias(app_id=app_id, alias=social_id)
    else:
        abort(400, 'At least one valid parameter social_id or user_id must be provided')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/associate_token')
@login_required
def get_associate_token(app_id):
    user_pk = request.args['user_id']
    provider = request.args['provider']
    if not is_valid_provider(provider):
        abort(400, 'Invalid provider')

    tups = (db.session.query(Users._id, SocialProfiles._id, SocialProfiles.provider)
            .join(SocialProfiles, and_(Users._id == SocialProfiles.user_id,
                                       Users.pk == user_pk, Users.app_id == app_id))).all()
    if not tups:
        abort(400, 'User not found')
    for tup in tups:
        if provider == tup[2]:
            abort(403, 'User already linked with another social profile for this provider')
    user_id = tups[0][0]

    try:
        log = AssociateLogs(provider=provider, app_id=app_id,
                            user_id=user_id,
                            nonce=gen_random_token(nbytes=32))
        associate_token = log.generate_associate_token()
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'token': associate_token,
            'associate_uri': url_for('authorize', _external=True,
                                     provider=provider, app_id=app_id,
                                     token=associate_token,
                                     intent=AuthLogs.INTENT_ASSOCIATE)
        })
    except Exception as e:
        logger.error(repr(e))
        raise
