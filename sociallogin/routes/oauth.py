from flask import abort, request, jsonify

from sociallogin import app as flask_app, logger
from sociallogin.entities import OAuthAuthorizeParams, OAuthCallbackParams
from sociallogin.exc import TokenParseError
from sociallogin.services import oauth as oauth_serv


@flask_app.route('/auth/<provider>', defaults={'intent': None})
@flask_app.route('/auth/<provider>/<intent>')
def authorize(provider, intent):
    params = OAuthAuthorizeParams(data=request.args, provider=provider, intent=intent)
    if not params.app_id or not params.success_callback:
        abort(400, 'Missing or invalid required parameters: app_id, callback_uri')

    resp = oauth_serv.authorize(params)
    return resp


@flask_app.route('/auth/<provider>/callback')
def web_authorize_callback(provider):
    params = OAuthCallbackParams(data=request.args, provider=provider)
    if not params.state:
        abort(400, 'Missing a required parameter: state')

    resp = oauth_serv.web_authorize_callback(params)
    return resp


@flask_app.route('/auth/<provider>/verify-token', methods=['POST'])
def mobile_authorize_callback(provider):
    params = OAuthCallbackParams(data=request.form, provider=provider)
    if not params.state or not params.access_token:
        abort(400, 'Missing or invalid required parameters: access token, state')

    params = OAuthCallbackParams(data=request.form, provider=provider)
    resp = oauth_serv.mobile_authorize_callback(params)
    return resp


@flask_app.route('/auth/profiles/authorized', methods=['POST'])
def get_authorized_profile():
    auth_token = request.form.get('auth_token')
    try:
        body = oauth_serv.get_authorized_profile(auth_token=auth_token, params=request.form)
        logger.debug('Profile authenticated', style='hybrid', **body)
        return jsonify(body)
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, auth_token=auth_token)
        abort(400, 'Invalid auth token')


@flask_app.route('/auth/profiles/activate', methods=['POST'])
def activate_profile():
    auth_token = request.form.get('auth_token')
    try:
        oauth_serv.activate_profile(auth_token=auth_token, params=request.form)
        return jsonify({'success': True})
    except TokenParseError as e:
        logger.warning('Parse auth token failed', error=e.description, auth_token=auth_token)
        abort(400, 'Invalid auth token')
