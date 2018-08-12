from flask import request, jsonify, redirect, url_for, abort
import base64
import hashlib
import uuid
import requests

from sociallogin import app, db


@app.route('/authorize/<provider>')
def handle_authorize(provider):
    return jsonify({'provider': provider})