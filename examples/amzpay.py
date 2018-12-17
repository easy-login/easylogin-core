import os
import html
import json
import time
import random
import logging

from flask import Flask, Blueprint, render_template, abort, url_for, redirect, \
    request, flash, session, current_app as app
from amazon_pay.client import AmazonPayClient


amazon_pay = Blueprint('amazon_pay', __name__,
                        static_folder='amazon_pay/static',
                        static_url_path='/amazon_pay',
                        template_folder='amazon-pay/templates')


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
    session['client_id'] = request.form['client-id']
    session['order_reference_id'] = 'S01-9969307-1083016'
    return redirect('/amazon-pay/cart')


@amazon_pay.route('/cart')
def cart():
    return render_template('cart.html')


@amazon_pay.route('/set', methods=['GET'])
def set():
    session['access_token'] = request.args.get('access_token')
    return render_template('set.html')


@amazon_pay.route('/confirm', methods=['POST'])
def confirm():
    from amazon_pay.client import AmazonPayClient

    pretty_confirm = None
    pretty_authorize = None

    client = AmazonPayClient(
        mws_access_key=session['mws_access_key'],
        mws_secret_key=session['mws_secret_key'],
        merchant_id=session['merchant_id'],
        sandbox=True,
        region='na',
        currency_code='USD',
        log_enabled=True,
        log_file_name="log.txt",
        log_level="DEBUG")
         
    print(session)
    response = client.confirm_order_reference(
        amazon_order_reference_id=session['order_reference_id'])

    pretty_confirm = json.dumps(
        json.loads(
            response.to_json()),
        indent=4)

    if response.success:
        response = client.authorize(
            amazon_order_reference_id=session['order_reference_id'],
            authorization_reference_id=rand(),
            authorization_amount='19.95',
            transaction_timeout=0,
            capture_now=False)

    pretty_authorize = json.dumps(
        json.loads(
            response.to_json()),
        indent=4)

    return render_template(
        'confirm.html', confirm=pretty_confirm, authorize=pretty_authorize)


@amazon_pay.route('/get_details', methods=['POST'])
def get_details():
    from amazon_pay.client import AmazonPayClient

    client = AmazonPayClient(
        mws_access_key=session['mws_access_key'],
        mws_secret_key=session['mws_secret_key'],
        merchant_id=session['merchant_id'],
        sandbox=True,
        region='na',
        currency_code='USD',
        log_enabled=True,
        log_file_name="log.txt",
        log_level="DEBUG")

    order_reference_id = request.form['orderReferenceId']
    session['order_reference_id'] = order_reference_id
    
    print(session['order_reference_id'])

    response = client.set_order_reference_details(
        amazon_order_reference_id=order_reference_id,
        order_total='19.95')

    if response.success:
        response = client.get_order_reference_details(
            amazon_order_reference_id=order_reference_id,
            address_consent_token=session['access_token'])

    pretty = json.dumps(
        json.loads(
            response.to_json()),
        indent=4)

    return pretty


def rand():
    return random.randint(0, 9999) + random.randint(0, 9999)

