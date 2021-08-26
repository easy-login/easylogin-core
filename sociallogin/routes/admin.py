from flask import request, render_template_string, \
    make_response, redirect, jsonify

from sociallogin import app as flask_app
from sociallogin.sec import jwt_token_helper
from sociallogin.services import admin as admin_serv

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
    ht = jwt_token_helper.generate(sub=origin, exp_in_seconds=600)
    resp.set_cookie('_ht', ht, secure=True)
    return resp


@flask_app.route('/hosted/auth/callback')
def hosted_auth_callback():
    token = request.args['token']
    ht = request.cookies['_ht']
    origin, _ = jwt_token_helper.decode(ht)
    print('request origin', origin)
    return render_template_string(html, token=token, origin=origin)


@flask_app.route('/admin/authenticate', methods=['POST'])
def admin_authenticate():
    email = request.form['email']
    password = request.form['password']

    resp = admin_serv.admin_authenticate(email, password)
    return jsonify(resp)


@flask_app.route('/admin/userinfo')
def admin_info():
    resp = admin_serv.admin_info(access_token=request.args.get('access_token'))
    return jsonify(resp)


@flask_app.route('/admin/convert_social_id', methods=['POST'])
def convert_social_id():
    body = request.form
    resp = admin_serv.convert_social_id(body)
    return jsonify(resp)
