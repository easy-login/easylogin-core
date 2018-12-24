import os
import html
import json
import time
import random
import logging
import secrets
import random

from flask import Flask, Blueprint, render_template, abort, url_for, redirect, \
    request, flash, session, current_app as app
from amazon_pay.client import AmazonPayClient

amazon_pay = Blueprint('amazon_pay', __name__,
                       static_folder='amazon_pay/static',
                       static_url_path='/amazon_pay',
                       template_folder='amazon-pay/templates')

REGION_CODE = 'jp'
CURRENCY_CODE = 'JPY'


@amazon_pay.route('/pay.html')
def show_pay():
    return render_template('pay.html')


@amazon_pay.route('/')
def index():
    return render_template('amzpay.html')


@amazon_pay.route('/settings', methods=['POST'])
def settings():
    session['merchant_id'] = request.form['merchant-id']
    session['mws_access_key'] = request.form['mws-access-key']
    session['mws_secret_key'] = request.form['mws-secret-key']
    session['order_reference_id'] = 'S01-9969307-1083016'
    return redirect('/amazon-pay/cart')


@amazon_pay.route('/cart')
def cart():
    items = [
        {
            'name': 'Easy Login Premium License 1 year',
            'description': 'This license will allow you to access all features for premium accounts at '
                           'easy-login.jp in 1 year.',
            'image_url': 'https://cdn3.iconfinder.com/data/icons/essential-rounded/66/Rounded-22-48.png',
            'price': random.randint(1, 5),
            'quantity': random.randint(1, 3)
        },
        {
            'name': 'Easy Login Premium License 3 years',
            'description': 'This license will allow you to access all features for premium accounts at '
                           'easy-login.jp in 3 years.',
            'image_url': 'https://cdn3.iconfinder.com/data/icons/free-social-1/60/Star-48.png',
            'price': random.randint(6, 10),
            'quantity': random.randint(1, 3)
        },
        {
            'name': 'Easy Login Premium License 5 years',
            'description': 'This license will allow you to access all features for premium accounts at '
                           'easy-login.jp in 5 years.',
            'image_url': 'https://cdn4.iconfinder.com/data/icons/ios-web-user-interface-multi-circle-flat-vol-5/512/'
                         'Crown_optimization_royal_princes_winner_premium_service-48.png',
            'price': random.randint(11, 20),
            'quantity': random.randint(1, 3)
        }
    ]
    amount = 0
    for item in items:
        amount += item['price'] * item['quantity']
    session['order_amount'] = str(amount * 1000)
    return render_template('cart.html', items=items, total_amount=str(amount) + ',000')


@amazon_pay.route('/set', methods=['GET'])
def set():
    if 'access_token' in request.args:
        session['amazon_Login_accessToken'] = request.args['access_token']
    else:
        session['amazon_Login_accessToken'] = request.cookies.get('amazon_Login_accessToken')
    return render_template('set.html')


@amazon_pay.route('/review', methods=['POST'])
def review():
    client = AmazonPayClient(
        mws_access_key=session['mws_access_key'],
        mws_secret_key=session['mws_secret_key'],
        merchant_id=session['merchant_id'],
        sandbox=True,
        region=REGION_CODE,
        currency_code=CURRENCY_CODE,
        log_enabled=True,
        log_file_name="/tmp/amzpay.log",
        log_level="DEBUG")

    order_reference_id = request.form['orderReferenceId']
    session['order_reference_id'] = order_reference_id

    print('get details for orderId', session['order_reference_id'])

    response = client.set_order_reference_details(
        amazon_order_reference_id=order_reference_id,
        order_total=session['order_amount'],
        seller_note='My seller note.',
        seller_order_id=secrets.token_hex(16),
        store_name='My store name.',
        custom_information='My custom information.')

    if response.success:
        response = client.get_order_reference_details(
            amazon_order_reference_id=order_reference_id,
            address_consent_token=session['amazon_Login_accessToken'])

    order_detail = json.dumps(json.loads(response.to_json()), indent=4)
    return render_template('review.html', order_detail=order_detail)


@amazon_pay.route('/confirm', methods=['POST'])
def confirm():
    pretty_confirm = None
    pretty_authorize = None

    client = AmazonPayClient(
        mws_access_key=session['mws_access_key'],
        mws_secret_key=session['mws_secret_key'],
        merchant_id=session['merchant_id'],
        sandbox=True,
        region=REGION_CODE,
        currency_code=CURRENCY_CODE,
        log_enabled=True,
        log_file_name="/tmp/amzpay.log",
        log_level="DEBUG")

    print('session', session)
    response = client.confirm_order_reference(
        amazon_order_reference_id=session['order_reference_id'])

    pretty_confirm = json.dumps(json.loads(response.to_json()), indent=4)

    if response.success:
        response = client.authorize(
            amazon_order_reference_id=session['order_reference_id'],
            authorization_reference_id=rand(),
            authorization_amount=session['order_amount'],
            transaction_timeout=0,
            capture_now=False)

    pretty_authorize = json.dumps(json.loads(response.to_json()), indent=4)

    return render_template(
        'confirm.html', confirm=pretty_confirm, authorize=pretty_authorize)


def rand():
    return random.randint(0, 9999) + random.randint(0, 9999)
