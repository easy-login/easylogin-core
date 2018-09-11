from sqlalchemy import *
from sqlalchemy.orm import *
import base64
import secrets

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

# nonce = secrets.token_hex(16)
# state = nonce + '.' + str(5)
# print(state)
# encoded = b64encode_string(state, urlsafe=True, padding=False)
# print(encoded)
# print(b64encode_string(state, urlsafe=True, padding=True))
# decoded = b64decode_string(encoded, urlsafe=True)
# print(decoded)


def test_args(*args, **kwargs):
    print(args)
    print_args(fullname='nhatanh', **kwargs)


def print_args(**kwargs):
    for key, value in kwargs.items():
        print('{}: {}'.format(key, value))


def update_dict(d1, d2=None, **kwargs):
    if d2:
        d1.update(d2)
    d1.update(kwargs)
    return d1


test_args('tjeubaoit', 28, **{'name': 'abu', 'age': 30})
d1 = {'name': 'abu'}
print(update_dict(d1, org='five9'))
