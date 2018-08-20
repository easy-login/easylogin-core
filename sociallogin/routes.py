from flask import request, jsonify, redirect, url_for, abort
import base64
import hashlib
import uuid
import requests
from flask_login import login_required, current_user as site

from sociallogin import app, db


@app.route('/users/link', methods=['PUT'])
@login_required
def link_user():
    return jsonify({'msg': 'ok', 'site_id': site._id})


@app.route('/users/unlink', methods=['PUT'])
@login_required
def unlink_user():
    return jsonify({'msg': 'ok'})


# GET /users/<userid|plusid>
@app.route('/users/<user_id>')
@login_required
def get_user(user_id):
    pass


# DELETE /users/<userid|plusid>
@app.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    pass


@app.route('/association_token', methods=['POST'])
@login_required
def get_association_token():
    pass