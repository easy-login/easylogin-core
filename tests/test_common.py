from sqlalchemy import *
from sqlalchemy.orm import *
import base64
import secrets
import urllib.parse as urlparse

from sociallogin.utils import b64decode_string, b64encode_string, add_params_to_uri


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


# test_args('tjeubaoit', 28, **{'name': 'abu', 'age': 30})
# d1 = {'name': 'abu'}
# print(update_dict(d1, org='five9'))

base_url = 'https://access.line.me/oauth2/v2.1/authorize'
url = add_params_to_uri(base_url,
                        client_id='2141412412',
                        scope=urlparse.quote('openid profile'),
                        state='ldshlsdgoi341049u12ldjlgj974kljfklsdf')
print(url)
