from flask import request, jsonify, redirect, url_for, abort

from sociallogin import app, db
from sociallogin.providers import get_auth_handler


# GET /auth/line?callback_uri=https://example.com/auth/approved
@app.route('/auth/<provider>')
def authenticate(provider):
    site_id = request.args.get('site_id')
    if not site_id:
        abort(404, 'Missing or invalid site_id')

    auth_handler = get_auth_handler(provider)
    if not auth_handler:
        abort(404, 'Invalid or unsupported provider')

    redirect_uri = url_for('authorize_callback', _external=True, provider=provider)
    authorize_uri = auth_handler.build_authorize_uri(provider, site_id, redirect_uri)
    return redirect(authorize_uri)


@app.route('/authorize/<provider>/approval_state')
def authorize_callback(provider):
    pass