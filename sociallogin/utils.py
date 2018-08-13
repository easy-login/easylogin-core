import base64
from flask import abort


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