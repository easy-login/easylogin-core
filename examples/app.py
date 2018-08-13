from flask import Flask, request

app = Flask(__name__)

@app.route('/auth/callback')
def auth_callback():
    token = request.args['token']
    print('token ==============> ', token)
    return '{"msg": "ok"}'

@app.route('/callback')
def callback():
    return '{"msg": "failed"}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)