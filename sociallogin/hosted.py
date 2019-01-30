from flask import request, render_template_string, \
    make_response, redirect

from sociallogin import app
from sociallogin.sec import jwt_token_service

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


@app.route('/hosted/auth/init')
def hosted_init_auth():
    return_url = request.args['return_url']
    origin = request.args['origin']
    resp = make_response(redirect(return_url))
    ht = jwt_token_service.generate(sub=origin, exp_in_seconds=600)
    resp.set_cookie('_ht', ht, secure=True)
    return resp


@app.route('/hosted/auth/callback')
def hosted_auth_callback():
    token = request.args['token']
    ht = request.cookies['_ht']
    origin, _ = jwt_token_service.decode(ht)
    print('request origin', origin)
    return render_template_string(html, token=token, origin=origin)
