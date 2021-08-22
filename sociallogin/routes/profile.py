from flask import abort, jsonify, request
from flask_login import login_required

from sociallogin import app as flask_app
from sociallogin.services import profile as profile_serv


@flask_app.route('/<int:app_id>/users/link', methods=['PUT'])
@login_required
def link_user(app_id):
    try:
        body = request.json
        profile_serv.link_user(app_id, body)
        return jsonify({'success': True})
    except KeyError as e:
        abort(400, 'Missing required field: ' + str(e))


@flask_app.route('/<int:app_id>/users/unlink', methods=['PUT'])
@login_required
def unlink_user(app_id):
    try:
        body = request.json
        num_affected = profile_serv.unlink_user(app_id, body)
        if not num_affected:
            abort(404, 'Social ID not found or not linked with any users')

        return jsonify({'success': True})
    except KeyError as e:
        abort(400, 'Missing required field: ' + str(e))


@flask_app.route('/<int:app_id>/users/merge', methods=['PUT'])
@login_required
def merge_user(app_id):
    body = request.json
    profile_serv.merge_user(app_id, body)
    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/disassociate', methods=['PUT'])
@login_required
def disassociate(app_id):
    body = request.json
    num_affected = profile_serv.disassociate(app_id, body)
    if not num_affected:
        abort(404, 'User ID or Social ID not found or not linked with each other')

    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users')
@login_required
def get_user(app_id):
    body = request.args
    resp = profile_serv.get_user(app_id, body)
    return jsonify(resp)


@flask_app.route('/<int:app_id>/users', methods=['DELETE'])
@login_required
def delete_user(app_id):
    body = request.json
    num_affected = profile_serv.delete_user(app_id, body)
    if not num_affected:
        abort(404, 'User ID or Social ID not found')

    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/delete_info', methods=['PUT'])
@login_required
def delete_user_info(app_id):
    body = request.json
    num_affected = profile_serv.delete_user_info(app_id, body)
    if not num_affected:
        abort(404, 'User ID or Social ID not found')

    return jsonify({'success': True})


@flask_app.route('/<int:app_id>/users/associate_token')
@login_required
def get_associate_token(app_id):
    body = request.args
    resp = profile_serv.get_associate_token(app_id, body)
    return jsonify(resp)
