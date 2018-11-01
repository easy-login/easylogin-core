import base64
import urllib.parse as urlparse
import hashlib
import hmac
import time
import os
import secrets
import string
import re
from datetime import timezone
import json
import logging

import pytz
import jwt
from flask import abort, current_app as app, request


class EasyLogger(object):

    STYLE_SIMPLE = 'simple'
    STYLE_INLINE = 'inline'
    STYLE_JSON = 'json'
    STYLE_HYBRID = 'hybrid'

    def __init__(self, impl, style=STYLE_INLINE):
        self.impl = impl
        self.style = style

    def load_from_config(self, config):
        self.style = config['LOG_STYLE']

    def debug(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.DEBUG, msg, style, *args, **kwargs)

    def info(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.INFO, msg, style, *args, **kwargs)

    def warning(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.WARNING, msg, style, *args, **kwargs)

    def warn(self, msg, *args, style=None, **kwargs):
        self.warning(msg, *args, style=style, **kwargs)

    def error(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, *args, **kwargs)

    def critical(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.CRITICAL, msg, style, *args, **kwargs)

    def exception(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, exc_info=1, *args, **kwargs)

    def _print_log(self, lvl, msg, style, *args, exc_info=0, **kwargs):
        if self.impl.level > lvl:
            return
        style = style or self.style
        if style == self.STYLE_INLINE:
            arg_str = ' '.join(args)
            kwarg_str = ' '.join(['%s=%s' % (k, self._check_quote(v)) 
                                 for k, v in kwargs.items()])
            msg += ' \t' + arg_str + '\t' + kwarg_str
        elif style == self.STYLE_JSON:
            msg = '\n' + json.dumps({
                'msg': msg,
                'args': args,
                'kwargs': kwargs
            }, ensure_ascii=False, indent=2)
        elif style == self.STYLE_HYBRID:
            msg += ' \t' + ' '.join(args)
            if kwargs:
                msg += '\n' + json.dumps(kwargs, indent=2)
        else:
            if args:
                msg += '\t' + str(args or '')
            if kwargs:
                msg += '\t' + str(kwargs or '')
        self.impl.log(lvl, '%s - %s' % (get_remote_ip(request), msg), exc_info=exc_info)

    @staticmethod
    def _check_quote(s):
        s = str(s)
        return '"%s"' % s if ' ' in s else s


def base64encode(b, urlsafe=False, padding=True):
    ob = base64.urlsafe_b64encode(b) if urlsafe else base64.standard_b64encode(b)
    encoded = ob.decode('ascii')
    if not padding:
        encoded = encoded.rstrip('=')
    return encoded


def base64decode(s, urlsafe=False):
    padding = 4 - (len(s) % 4)
    s += ('=' * padding)
    b = s.encode('ascii')
    ob = base64.urlsafe_b64decode(b) if urlsafe else base64.standard_b64decode(b)
    return ob


def b64encode_string(s, urlsafe=False, padding=True, charset='utf8'):
    b = s.encode(charset)
    return base64encode(b, urlsafe, padding)


def b64decode_string(s, urlsafe=False, charset='utf8'):
    ob = base64decode(s, urlsafe)
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
    }, key=app.config['SECRET_KEY'], algorithm='HS256').decode('utf8')


def decode_jwt(encoded):
    try:
        payload = jwt.decode(encoded, key=app.config['SECRET_KEY'],
                             issuer=app.config['SERVER_NAME'], algorithms=['HS256'])
        expire = payload.get('exp', 0)
        if expire < int(time.time()):
            raise TimeoutError()
        return payload['sub'], payload['data']
    except (jwt.exceptions.PyJWTError, KeyError):
        return None


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
    return base64encode(hashed.digest()).rstrip('\n')
