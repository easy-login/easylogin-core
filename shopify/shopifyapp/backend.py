import sys
import secrets
from urllib import parse as up
import hashlib

from flask import request, url_for, redirect, abort
import requests

from shopifyapp import app, db, logger
from shopifyapp.utils import add_params_to_uri, calculate_hmac
from shopifyapp.models import Stores, AccessTokens


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
    resp = redirect(uri)
    resp.set_cookie('shopifyState', state)
    return resp


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

    # state = args.get('state')
    # expected_state = request.cookies.get('shopifyState')
    # if state != expected_state:
    #     logger.warning('OAuth state did not match', state=state, expected=expected_state)
    #     abort(403, 'State origin did not match')

    shop = args['shop']
    store_id = db.session.query(Stores._id).filter_by(store_url=shop).scalar()
    if not store_id:
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
    access_token = AccessTokens(access_token=tokens['access_token'], store_id=store_id)
    db.session.add(access_token)
    db.session.commit()

    return redirect('https://' + shop + '/account/login')
