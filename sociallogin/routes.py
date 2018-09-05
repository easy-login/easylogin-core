from datetime import datetime

from flask import abort, jsonify, request, url_for
from flask_login import login_required, current_user as current_app
from sqlalchemy import func

from sociallogin import app as flask_app, db, logger
from sociallogin.models import SocialProfiles, Users, AuthLogs, AssociateLogs
from sociallogin.utils import gen_random_token
from sociallogin.providers import is_valid_provider


@flask_app.route('/<int:app_id>/profiles/authorized')
@login_required
def authorized_profile():
    token = request.args.get('token')
    if not token:
        abort(400, 'Missing parameter token')

    log = AuthLogs.find_by_one_time_token(auth_token=token)
    if not log or log.status != AuthLogs.STATUS_AUTHORIZED:
        abort(400, 'Invalid token or token has been already used')
    elif log.token_expires < datetime.now():
        abort(400, 'Token expired')

    try:
        log.status = AuthLogs.STATUS_SUCCEEDED
        profile = SocialProfiles.query.filter_by(_id=log.social_id).first_or_404()
        logger.debug('Authorized profile: ' + repr(profile))
        db.session.commit()
        return jsonify(profile.as_dict())
    except Exception as e:
        logger.error(repr(e))
        log.status = AuthLogs.STATUS_FAILED
        raise


@flask_app.route('/<int:app_id>/users/link', methods=['PUT'])
@login_required
def link_user(app_id):
    body = request.json
    social_id = int(body['social_id'])
    user_pk = body['user_id']

    profile = SocialProfiles.query.filter_by(_id=social_id).one_or_none()
    if not profile or profile.app_id != app_id:
        abort(404, 'Social ID not found')
    if profile.user_id:
        abort(409, 'Social profile already linked with an exists user')

    profile.link_to_end_user(user_pk)
    db.session.commit()

    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/unlink', methods=['PUT'])
@login_required
def unlink_user(app_id):
    body = request.json
    user_pk = body['user_id']

    if 'social_id' in body:
        social_id = int(body['social_id'])
        profile = SocialProfiles.query.filter_by(_id=social_id).one_or_none()
        if not profile or profile.app_id != app_id:
            abort(404, 'Social ID not found')
        if not profile.user_id:
            abort(409, "Social profile doesn't link with any user")

        profile.unlink_from_end_user(user_pk)
    elif 'providers' in body:
        providers = body['providers'].split(',')
        SocialProfiles.unlink_by_provider(app_id=app_id, user_pk=user_pk, providers=providers)
        return jsonify({'success': True})
    else:
        abort(400, 'At least one parameter social_id or providers must be provided')

    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users')
@login_required
def get_user(app_id):
    args = request.args
    user_pk = args.get('user_id')
    social_id = args.get('social_id')

    if user_pk:
        return jsonify(Users.get_full_as_dict(app_id=app_id, pk=user_pk))
    elif social_id:
        profile = SocialProfiles.query.filter_by(_id=social_id).one_or_none()
        if not profile or profile.app_id != app_id:
            abort(404, 'Social ID not found')
        if profile.user_pk:
            return jsonify(Users.get_full_as_dict(app_id=app_id, pk=profile.user_pk))
        else:
            return jsonify({
                'user': None,
                'profiles': [profile.as_dict()]
            })
    else:
        abort(400, 'At least one parameter social_id or user_id must be provided')


@flask_app.route('/<int:app_id>/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(app_id, user_id):
    pass


@flask_app.route('/<int:app_id>/users/associate_token')
@login_required
def get_associate_token(app_id):
    user_pk = request.args['user_id']
    provider = request.args['provider']
    if not is_valid_provider(provider):
        abort(404, 'Invalid provider')

    (user_id,) = (db.session.query(Users._id)
                  .filter_by(app_id=app_id, pk=user_pk).one_or_none()) or (None,)
    if not user_id:
        abort(404, 'User ID not found')

    (social_id,) = (db.session.query(SocialProfiles._id)
                    .filter_by(app_id=app_id,
                               user_pk=user_pk,
                               provider=provider).one_or_none()) or (None,)
    if social_id:
        abort(403, 'User already linked with another social profile for this provider')

    try:
        nonce = gen_random_token(nbytes=32)
        log = AssociateLogs.add_or_reset(provider=provider, app_id=app_id,
                                         user_id=user_id, nonce=nonce)
        associate_token = log.generate_associate_token()
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
