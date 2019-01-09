import sys
import secrets
from urllib import parse as up
import hashlib

from flask import request, url_for, redirect, abort, render_template, \
    make_response, jsonify, session
import requests

from shopifyapp import app, db, logger
from shopifyapp.utils import add_params_to_uri, calculate_hmac
from shopifyapp.models import Stores, AccessTokens
from shopifyapp.apiclient import ShopifyClient


def support_jsonp(f):
    """Wraps JSONified output for JSONP"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            content = str(callback) + '(' + f().data.decode('utf8') + ')'
            return app.response_class(content, mimetype='application/json')
        else:
            return f(*args, **kwargs)

    return decorated_function


@app.route('/hosted/shopify')
def install():
    shop = request.args.get('shop')
    # ts = int(request.args.get('timestamp'))
    # hmac = request.args.get('hmac')

    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        logger.debug('Store does not exists in db, create new', store=shop)
        store = Stores(store_url=shop)
        db.session.add(store)
        db.session.commit()
    if store.access_token:
        shopify_client = ShopifyClient(shop_url=shop, access_token=store.access_token)
        r = shopify_client.get_shop_info()
        if r.success:
            return render_config_page(
                shop=shop,
                app_id=store.app_id,
                api_key=store.api_key
            )
    scopes = [
        'read_customers', 'write_customers',
        'read_script_tags', 'write_script_tags',
        'read_themes', 'write_themes'
    ]
    state = secrets.token_hex(nbytes=16)
    uri = add_params_to_uri(
        uri='https://' + shop + '/admin/oauth/authorize',
        client_id=app.config['SHOPIFY_OAUTH_CLIENT_ID'],
        redirect_uri=url_for('oauth_callback', _external=True),
        scope=','.join(scopes),
        nonce=state)
    logger.debug('Redirect to Shopify authorize URL', uri)
    return redirect(uri)


@app.route('/hosted/shopify/oauth/callback')
def oauth_callback():
    args = {}
    logger.debug('Callback request args', style='hybrid', **request.args)
    for k, v in request.args.items():
        if k != 'hmac':
            args[k] = v
    query = up.urlencode(args)
    sign = request.args['hmac']
    expected_sign = calculate_hmac(key=app.config['SHOPIFY_OAUTH_CLIENT_SECRET'],
                                   raw=query, digestmod=hashlib.sha256)
    if sign != expected_sign:
        logger.warning('HMAC signature invalid', sign=sign, expected=expected_sign)
        abort(403, 'HMAC signature invalid')

    shop = args['shop']
    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        abort(404, 'Store not found')
    r = requests.post(
        url='https://' + shop + '/admin/oauth/access_token',
        data={
            'client_id': app.config['SHOPIFY_OAUTH_CLIENT_ID'],
            'client_secret': app.config['SHOPIFY_OAUTH_CLIENT_SECRET'],
            'code': args['code']
        })
    if r.status_code != 200:
        abort(500, 'Unknown error. Cannot get Shopify access token')
        logger.warn('Get Shopify access token failed', **r.json())

    tokens = r.json()
    Stores.set_installed(store_url=shop, access_token=tokens['access_token'])
    db.session.commit()
    return redirect(url_for('install'))


@app.route('/hosted/shopify/<shop>/config', methods=['POST'])
def update_config(shop):
    try:
        csrf_token = request.form['csrf_token']
        expected_token = session['csrf_token']
        if csrf_token != expected_token:
            abort(403, 'CSRF token invalid')

        easylogin_app_id = request.form['easylogin_app_id']
        easylogin_api_key = request.form['easylogin_api_key']
        Stores.update_easylogin_config(
            store_url=shop,
            app_id=easylogin_app_id,
            api_key=easylogin_api_key)
        db.session.commit()
        return render_config_page(
            shop=shop,
            app_id=easylogin_app_id,
            api_key=easylogin_api_key)
    except KeyError:
        abort(400, 'Missing or invalid parameters')


@app.route('/hosted/shopify/<shop>/auth/<provider>')
def get_auth_url(shop, provider):
    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        abort(404, 'Store URL not found')
    if provider not in ['line', 'yahoojp', 'facebook']:
        abort(400, 'Invalid provider')
    uri = add_params_to_uri(
        uri='https://api.easy-login.jp/auth/' + provider,
        app_id=store.easylogin_app_id,
        callback_uri=url_for('install', _external=True),
        nonce=secrets.token_hex(nbytes=16))
    return redirect(uri)


@app.route('/hosted/shopify/<shop>/login-buttons/jsonp')
@support_jsonp
def get_login_buttons_html(shop):
    callback = request.args.get('callback')
    html = """
    <div id="SocialAuthForm" class="col-md-6">
        <h4 class="text-center">OR</h4>
        <div class="login-form line-form">
            <a href="/hosted/shopify/{shop}/auth/line">
            <button class="line-btn">Login with LINE</button>
            </a>
        </div>
        <div class="login-form yahoo-form">
            <a href="hosted/shopify/{shop}/auth/yahoojp">
            <button class="yahoo-btn">Login with YAHOOJP</button>
            </a>
        </div>
        <div class="login-form facebook-form">
            <a href="hosted/shopify/{shop}/auth/facebook">
            <button class="facebook-btn">Login with FACEBOOK</button>
            </a>
        </div>
    </div>
    """.strip().format(shop=shop)
    return html
    # return callback + '(' + html + ');';


def render_config_page(shop, app_id, api_key):
    csrf_token = secrets.token_urlsafe(nbytes=64)
    session['csrf_token'] = csrf_token
    return render_template(
        'config.html',
        shop=shop, csrf_token=csrf_token,
        app_id=app_id or '',
        api_key=api_key or '')
