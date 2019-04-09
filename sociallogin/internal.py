from flask import request, render_template_string, \
    make_response, redirect, jsonify, abort
from passlib.hash import django_pbkdf2_sha256

from sociallogin import app as flask_app, db, logger
from sociallogin.sec import jwt_token_service
from sociallogin.models import SocialProfiles, Admins, Apps
from sociallogin.exc import TokenParseError

html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Easy Login</title>
</head>
<body>
<script>
  var opener = window.opener;
  if(opener) {
    opener.postMessage("{{ token }}", "{{ origin }}");
  }
  window.close();
</script>
</body>
</html>
"""


@flask_app.route('/hosted/auth/init')
def hosted_init_auth():
    return_url = request.args['return_url']
    origin = request.args['origin']
    resp = make_response(redirect(return_url))
    ht = jwt_token_service.generate(sub=origin, exp_in_seconds=600)
    resp.set_cookie('_ht', ht, secure=True)
    return resp


@flask_app.route('/hosted/auth/callback')
def hosted_auth_callback():
    token = request.args['token']
    ht = request.cookies['_ht']
    origin, _ = jwt_token_service.decode(ht)
    print('request origin', origin)
    return render_template_string(html, token=token, origin=origin)


@flask_app.route('/admin/authenticate', methods=['POST'])
def admin_authenticate():
    email = request.form['email']
    password = request.form['password']

    admin = Admins.query.filter_by(email=email).one_or_none()
    if not admin:
        abort(404, 'Email not found')
    if not django_pbkdf2_sha256.verify(secret=password, hash=admin.password):
        abort(401, 'Invalid authorization credentials')

    admin_attrs = admin.as_dict()
    return jsonify({
        'user': admin_attrs,
        'access_token': jwt_token_service.generate(
            sub=admin._id,
            exp_in_seconds=86400 * 365,
            **admin_attrs,
        )
    })


@flask_app.route('/admin/userinfo')
def admin_info():
    sub, _ = _validate_access_token(access_token=request.args['access_token'])
    admin = Admins.query.filter_by(_id=sub).one_or_none()
    if not admin:
        abort(404, 'Email not found')
    return jsonify({'user': admin.as_dict()})


@flask_app.route('/admin/convert_social_id', methods=['POST'])
def convert_social_id():
    sub, _ = _validate_access_token(access_token=request.form['access_token'])
    app_id = request.form['app_id']
    owner_id = db.session.query(Apps.owner_id).filter_by(_id=app_id).scalar()
    if not owner_id or owner_id != sub:
        abort(404, 'App ID not found')

    social_ids = request.form['ids'].split(',')
    if len(social_ids) > 150:
        abort(400, 'Number of IDs cannot be larger than 150')

    scope_ids = SocialProfiles.social_id_to_scope_id(app_id=app_id, social_ids=social_ids)
    return jsonify([e[0] for e in scope_ids])


def _validate_access_token(access_token):
    try:
        return jwt_token_service.decode(token=access_token)
    except TokenParseError as e:
        logger.warning('Parse admin access token failed', error=e.description, token=access_token)
        abort(401, 'Invalid access token')
