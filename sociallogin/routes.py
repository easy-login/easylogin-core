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
    try:
        log = AuthLogs.find_by_once_token(once_token=token)
        if log.status != AuthLogs.STATUS_AUTHORIZED:
            abort(400, 'Invalid token or token has been already used')
        elif log.token_expires < datetime.now():
            abort(400, 'Token expired')
        social_id = log.social_id
        log.status = AuthLogs.STATUS_SUCCEEDED
        profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404().as_dict()
        return jsonify(profile)
    finally:
        db.session.commit()


@flask_app.route('/users/link', methods=['PUT'])
@login_required
def link_user():
    body = request.json
    social_id = int(body['social_id'])
    user_id = body['user_id']
    app_id = current_app._id

    profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404()
    if profile.app_id != app_id:
        abort(404, 'Social ID not found')
    if profile.user_id:
        abort(409, 'Social profile already linked with an exists user')
    # count = db.session.query(func.count(SocialProfiles._id)).filter_by(user_id=user_id).scalar()
    # if count > 0:
    #     abort(409, 'User already linked with other social profiles')

    user = Users.query.filter_by(_id=user_id)
    if user:
        if user.app_id != app_id:
            abort(404, )
        pass
    else:
        user = Users(_id=user_id, 
            app_id=app_id, 
            last_provider=profile.provider, 
            login_count=1)
        db.session.add(user)
    profile.user_id = user_id
    db.session.commit()
    return jsonify({'success': True})


@flask_app.route('/users/unlink', methods=['PUT'])
@login_required
def unlink_user():
    return jsonify({'msg': 'ok'})


# GET /users/<userid|socialid>
@flask_app.route('/users')
@login_required
def get_user():
    args = request.args
    user_id = args.get('user_id')
    social_id = args.get('social_id')
    if user_id:
        pass
    elif social_id:
        profile = SocialProfiles.query.filter_by(_id=social_id).first_or_404()
        return jsonify(profile.as_dict())
    else: 
        abort(404)



# DELETE /users/<userid|plusid>
@flask_app.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    pass


@flask_app.route('/association_token', methods=['POST'])
@login_required
def get_association_token():
    pass
