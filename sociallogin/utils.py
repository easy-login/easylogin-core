import base64
from flask import abort, current_app as app, jsonify
import urllib.parse as urlparse
import hashlib
import hmac
import jwt
import time
import os
import secrets
import string
import re
from datetime import datetime, timedelta, timezone
import pytz


def b64encode_string(s, urlsafe=False, padding=True, charset='utf8'):
    ib = s.encode(charset)
    ob = base64.urlsafe_b64encode(ib) if urlsafe else base64.standard_b64encode(ib)
    encoded = ob.decode('ascii')
    if not padding:
        encoded = encoded.rstrip('=')
    return encoded


def b64decode_string(s, urlsafe=False, charset='utf8'):
    padding = 4 - (len(s) % 4)
    s += ('=' * padding)
    ib = s.encode('ascii')
    ob = base64.urlsafe_b64decode(ib) if urlsafe else base64.standard_b64decode(ib)
    return ob.decode(charset)


def get_or_abort(d, key, err_msg=None, code=400):
    try:
        return d[key]
    except KeyError as err:
        abort(code, err_msg or str(err))


def is_same_uri(url1, url2):
    r1 = urlparse.urlparse(url1)
    r2 = urlparse.urlparse(url2)
    return r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path


def gen_random_token(nbytes=32, format='alphanumeric'):
    if format == 'alphanumeric':
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(nbytes))
    elif format == 'hex':
        return secrets.token_hex(nbytes)
    elif format == 'urlsafe':
        return secrets.token_urlsafe(nbytes)
    elif format == 'base64':
        return base64.standard_b64encode(secrets.token_bytes(nbytes))
    else:
        return os.urandom(nbytes)


def gen_jwt_token(sub, exp_in_seconds, **kwargs):
    now = int(time.time())
    return jwt.encode({
        'iss': app.config['SERVER_NAME'],
        'sub': sub,
        'exp': now + exp_in_seconds,
        'iat': now,
        'data': kwargs
    }, key=app.config['JWT_SECRET_KEY'], algorithm='HS256').decode('utf8')


def decode_jwt(encoded):
    try:
        payload = jwt.decode(encoded, key=app.config['JWT_SECRET_KEY'], 
                             issuer=app.config['SERVER_NAME'], algorithms=['HS256'])
        expire = payload.get('exp', 0)
        if expire < int(time.time()):
            raise TimeoutError()
        return payload['sub'], payload['data']
    except (jwt.exceptions.PyJWTError, KeyError):
        return None


def make_api_response(payload, success=True):
    return jsonify({'success': success}) if payload else jsonify({
        'success': success,
        'data': payload
    })


def convert_CameCase_to_snake_case(s):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def add_params_to_uri(uri, **kwargs):
    query = urlparse.urlencode(kwargs, safe='', quote_via=urlparse.quote)
    return uri + ('?' if uri.find('?') < 0 else '&') + query


def update_dict(d1, d2=None, **kwargs):
    if d2:
        d1.update(d2)
    d1.update(kwargs)
    return d1


def get_remote_ip(req):
    if req.environ.get('HTTP_X_FORWARDED_FOR'):
        return req.environ['HTTP_X_FORWARDED_FOR']
    elif req.environ.get('HTTP_X_REAL_IP'):
        return req.environ['HTTP_X_REAL_IP']
    else:
        return req.remote_addr


def convert_to_user_timezone(dt):
    tz = pytz.timezone(app.config['TIME_ZONE'])
    return dt.replace(tzinfo=timezone.utc).astimezone(tz)


def calculate_hmac(key, raw, digestmod=hashlib.sha1):
    hashed = hmac.new(key.encode('utf8'), raw.encode('utf8'), digestmod=digestmod)
    return base64.standard_b64encode(hashed.digest()).decode('ascii').rstrip('\n')
