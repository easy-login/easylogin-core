from flask import request, jsonify, redirect, url_for, abort
import base64
import hashlib
import uuid
import requests

from sociallogin import app, db


@app.route('/users/link', methods = ['PUT'])
def link_user():
    pass


# PUT /users/<userid>/unlink?api_key=xxx
@app.route('/users/unlink', methods = ['PUT'])
def unlink_user():
    pass


# GET /users/<userid|plusid>
@app.route('/users/<user_id>')
def get_user(user_id):
    pass


# DELETE /users/<userid|plusid>
@app.route('/users/<user_id>')
def delete_user(user_id):
    pass


@app.route('/association_token')
def get_association_token():
    pass
    