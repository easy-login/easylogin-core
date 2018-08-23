import base64
import hashlib
import uuid
from datetime import datetime

import requests
from flask import abort, jsonify, redirect, request, url_for
from flask_login import login_required, current_user as current_app
from sqlalchemy import func

from sociallogin import app as flask_app, db
from sociallogin.models import AuthLogs, SocialProfiles, Users
from sociallogin.utils import make_api_response


@flask_app.route('/profiles/authenticated')
@login_required
def authenticated_profile():
    token = request.args.get('token')
    if not token:
        abort(400, 'Missing parameter token')

    log = AuthLogs.find_by_once_token(once_token=token)
    if log.status != AuthLogs.STATUS_AUTHORIZED:
        abort(400, 'Invalid token or token has been already used')
    elif log.token_expires < datetime.now():
        abort(400, 'Token expired')

    try:
        log.status = AuthLogs.STATUS_SUCCEEDED
        social_id = log.social_id
        profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404()
        Users.update_after_auth(profile)

        return jsonify(profile.as_dict())
    finally:
        db.session.commit()


@flask_app.route('/users/link', methods=['PUT'])
@login_required
def link_user():
    body = request.json
    social_id = int(body['social_id'])
    user_pk = body['user_id']
    app_id = current_app._id

    profile = SocialProfiles.query.filter_by(app_id=app_id, _id=social_id).first_or_404()
    if profile.user_id:
        abort(409, 'Social profile already linked with an exists user')

    Users.link_with_social_profile(app_id, user_pk, profile)
    db.session.commit()

    return jsonify({'success': True})


@flask_app.route('/users/unlink', methods=['PUT'])
@login_required
def unlink_user():
    body = request.json
    user_pk = body['user_id']
    app_id = current_app._id
    try:
        if 'social_id' in body:
            social_id = int(body['social_id'])
            profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404()
            if not profile.user_id:
                abort(409, "Social profile doesn't link with any user")
            profile.unlink_from_end_user(user_pk)
            return jsonify({'success': True})
        elif 'providers' in body:
            providers = body['providers'].split(',')
            SocialProfiles.unlink_by_provider(app_id=app_id, user_pk=user_pk, providers=providers)
            return jsonify({'success': True})
        else:
            abort(400, 'Missing parameter social_id or providers')
    finally:
        db.session.commit()


@flask_app.route('/users')
@login_required
def get_user():
    args = request.args
    user_pk = args.get('user_id')
    social_id = args.get('social_id')
    app_id = current_app._id

    if user_pk:
        return jsonify(Users.get_full_as_dict(app_id=app_id, pk=user_pk))
    elif social_id:
        profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404()
        if profile.user_pk:
            return jsonify(Users.get_full_as_dict(app_id=app_id, pk=profile.user_pk))
        else:
            return jsonify({
                'user': None,
                'profiles': [profile.as_dict()]
            })
    else:
        abort(404, 'User not found')


@flask_app.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    pass


@flask_app.route('/association_token', methods=['POST'])
@login_required
def get_association_token():
    pass
