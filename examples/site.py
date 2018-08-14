from flask import Flask, request, render_template, jsonify

app = Flask(__name__, template_folder='.')

@app.route('/auth/callback')
def auth_callback():
    token = request.args['token']
    provider = request.args['provider']
    return render_template('demo.html', provider=provider, token=token)

@app.route('/demo.html')
def demo_page():
    return render_template('demo.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)