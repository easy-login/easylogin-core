import base64
from flask import abort, current_app as app
import urllib.parse as urlparse
import uuid
import hashlib
import jwt
import time


def b64encode_string(s, urlsafe=False, charset='utf8'):
    ib = s.encode(charset)
    ob = base64.urlsafe_b64encode(ib) if urlsafe else base64.standard_b64encode(ib) 
    return ob.decode('ascii')


def b64decode_string(s, urlsafe=False, charset='utf8'):
    ib = s.encode('ascii')
    ob = base64.urlsafe_b64decode(ib) if urlsafe else base64.standard_b64decode(ib)
    return ob.decode(charset)


def get_or_abort(d, key, err_msg=None, code=404):
    try:
        return d[key]
    except KeyError as err:
        abort(code, err_msg or err.message)


def gen_unique_int64():
    pass


def is_same_uri(url1, url2):
    r1 = urlparse.urlparse(url1)
    r2 = urlparse.urlparse(url2)
    return r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path


def gen_random_token():
    return hashlib.sha1(uuid.uuid4().bytes).hexdigest()


def gen_jwt_token(sub, exp_in_seconds):
    now = int(time.time())
    return jwt.encode({
        'iss': app.config['SERVER_NAME'],
        'sub': sub,
        'exp': now + exp_in_seconds,
        'iat': now
    }, app.config['JWT_SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM']).decode('utf8')