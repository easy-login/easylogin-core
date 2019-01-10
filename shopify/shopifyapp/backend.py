import secrets
from urllib import parse as up
import hashlib
import json

from flask import request, url_for, redirect, abort, render_template, \
    make_response, jsonify, session
import requests

from shopifyapp import app, db, logger
from shopifyapp.utils import add_params_to_uri, calculate_hmac, support_jsonp
from shopifyapp.models import Stores, Customers
from shopifyapp.apiclient import ShopifyClient, EasyLoginClient


@app.route('/shopify')
def install():
    shop = request.args.get('shop')
    # ts = int(request.args.get('timestamp'))
    # hmac = request.args.get('hmac')
    if not shop or not shop.endswith('.myshopify.com'):
        abort(400, 'Invalid shop')

    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        logger.debug('Store does not exists in db, create new', store=shop)
        store = Stores(store_url=shop)
        db.session.add(store)
    if store.access_token:
        shopify_client = ShopifyClient(shop_url=shop, access_token=store.access_token)
        r = shopify_client.get_shop_info()
        if r.success:
            logger.debug('Store has installed', style='hybrid', **store.as_dict())
            return render_config_page(
                shop=shop,
                app_id=store.easylogin_app_id,
                api_key=store.easylogin_api_key
            )
    logger.info('Store did not installed', store_url=shop)
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

    db.session.commit()
    return redirect(uri)


@app.route('/shopify/oauth/callback')
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
        logger.error('Get Shopify access token failed', **r.json())

    tokens = r.json()
    Stores.set_installed(store_url=shop, access_token=tokens['access_token'])
    db.session.commit()
    return redirect('https://' + shop + '/admin/apps/' + app.config['SHOPIFY_APP_NAME'])


@app.route('/shopify/<shop>/config', methods=['POST'])
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


@app.route('/shopify/<shop>/auth/<provider>')
def get_auth_url(shop, provider):
    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        abort(404, 'Store URL not found')
    if provider not in ['line', 'yahoojp', 'facebook']:
        abort(400, 'Invalid provider')
    uri = add_params_to_uri(
        uri='https://api.easy-login.jp/auth/' + provider,
        app_id=store.easylogin_app_id,
        callback_uri=url_for('easylogin_callback', shop=shop, _external=True),
        nonce=secrets.token_hex(nbytes=16))
    return redirect(uri)


@app.route('/shopify/<shop>/buttons')
@support_jsonp
def get_login_buttons_html(shop):
    html = """
    <div id="SocialAuthForm" class="col-md-6">
        <h4 class="text-center">OR</h4>
        <div class="login-form line-form">
            <a href="{line_url}">
            <button class="line-btn">Login with LINE</button>
            </a>
        </div>
        <div class="login-form yahoo-form">
            <a href="{yahoo_url}">
            <button class="yahoo-btn">Login with YAHOOJP</button>
            </a>
        </div>
        <div class="login-form facebook-form">
            <a href="{facebook_url}">
            <button class="facebook-btn">Login with FACEBOOK</button>
            </a>
        </div>
    </div>
    """.strip().format(
        line_url=url_for('get_auth_url', shop=shop, provider='line', _external=True),
        yahoo_url=url_for('get_auth_url', shop=shop, provider='yahoojp', _external=True),
        facebook_url=url_for('get_auth_url', shop=shop, provider='facebook', _external=True)
    )
    return jsonify({'html': html})


@app.route('/shopify/<shop>/auth/callback')
def easylogin_callback(shop):
    provider = request.args.get('provider')
    token = request.args.get('token')
    if not provider or not token:
        abort(400, 'Missing or invalid input parameters')
    logger.debug('Request URL', request.url)

    store = Stores.query.filter_by(store_url=shop).one_or_none()
    if not store:
        abort(404, 'Store not found')
    easylogin_client = EasyLoginClient(
        app_id=store.easylogin_app_id,
        api_key=store.easylogin_api_key
    )
    shopify_client = ShopifyClient(
        shop_url=store.store_url,
        access_token=store.access_token
    )

    r = easylogin_client.get_authorized_profile(access_token=token)
    if r.failed:
        raise_error(500, 'EasyLogin API error', data=r.json())

    profile = r.json()
    logger.debug('authorized profile', json.dumps(profile, indent=2, ensure_ascii=False))
    attrs = profile.get('attrs', {})
    email = attrs.get('email')
    if not email:
        abort(403, 'Cannot log in without customer email')

    r = shopify_client.search_customer(email=email, fields='id,email,first_name,last_name')
    if r.failed:
        raise_error(500, 'Shopify API error', data=r.json())

    password = secrets.token_urlsafe(nbytes=16)
    customers = r.json()['customers']
    logger.debug('shopify customers', customers)

    if customers:
        customer = customers[0]
        customer.update({
            'password': password,
            'password_confirmation': password
        })
        r = shopify_client.update_customer(customer_id=customer['id'], customer=customer)
        if r.failed:
            raise_error(500, 'Shopify API error', data=r.json())

        Customers.add_or_update(**customer)
        logger.debug('update customer info success', r.json()['customer'])
    else:
        first_name = ''
        last_name = email
        if provider == 'line':
            last_name = attrs.get('displayName', last_name)
        elif provider == 'facebook':
            first_name = attrs.get('first_name', first_name)
            last_name = attrs.get('last_name', last_name)
        elif provider == 'yahoojp':
            first_name = attrs.get('given_name', first_name)
            last_name = attrs.get('family_name', last_name)
        logger.debug('create new customer', first_name, last_name, email)

        customer = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'verified_email': True,
            'password': password,
            'password_confirmation': password,
            'send_email_welcome': False
        }
        r = shopify_client.create_customer(customer=customer)
        if r.failed:
            raise_error(500, 'Shopify API error', data=r.json())

        customer = r.json()['customer']
        Customers.add_or_update(
            id=customer['id'],
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        logger.debug('Create customer success', json.dumps(customer, indent=2))

    easylogin_social_id = profile['social_id']
    customer_id = customer['id']
    if not profile.get('user_id'):
        r = easylogin_client.get_user_profile(user_id=customer_id)
        if r.failed:
            if r.status_code != 404:
                logger.debug(r.status_code, r.text)
                raise_error(500, 'EasyLogin API error', data=r.json())
            r = easylogin_client.link_social_profile_with_user(
                social_id=easylogin_social_id,
                user_id=customer_id)
            if r.failed:
                raise_error(500, 'EasyLogin API error', data=r.json())
            logger.debug('Link easylogin social ID with shopify customer ID success',
                         easylogin_social_id, customer_id)
        else:
            r = easylogin_client.merge_user(
                src_social_id=easylogin_social_id,
                dst_user_id=customer_id)
            if r.failed:
                raise_error(500, 'EasyLogin API error', data=r.json())
            logger.debug('Merge easylogin user success', easylogin_social_id, customer_id)

    db.session.commit()
    params = up.urlencode({'k': email, 's': password})
    return redirect('https://{}/account/login?{}#abc'.format(shop, params))


def raise_error(code, msg, data):
    logger.debug(msg, code=code, data=json.dumps(data, indent=2, ensure_ascii=False))
    abort(code, msg)


def render_config_page(shop, app_id, api_key):
    csrf_token = secrets.token_urlsafe(nbytes=64)
    session['csrf_token'] = csrf_token
    return render_template(
        'config.html',
        shop=shop, csrf_token=csrf_token,
        app_id=app_id or '',
        api_key=api_key or '')
