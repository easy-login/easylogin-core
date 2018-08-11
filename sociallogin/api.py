from flask import request, jsonify, redirect, url_for, abort
import base64t hashlib
import uuid
import requests

from sociallogin import app

@app.route('/authorize/<provider')
def handle_authorize():
    pass