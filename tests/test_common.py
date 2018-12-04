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

# base_url = 'https://access.line.me/oauth2/v2.1/authorize'
# url = add_params_to_uri(base_url,
#                         client_id='2141412412',
#                         scope=urlparse.quote('openid profile'),
#                         state='ldshlsdgoi341049u12ldjlgj974kljfklsdf')
# print(url)

profile = """
{"resourceName": "people/116622784508820350508", "etag": "%EhIBAj0DBwgJPgoLPxBAGTQ3JS4aDAECAwQFBgcICQoLDA==", "locales": [{"metadata": {"primary": true, "source": {"type": "ACCOUNT", "id": "116622784508820350508"}}, "value": "vi"}], "names": [{"metadata": {"primary": true, "source": {"type": "PROFILE", "id": "116622784508820350508"}}, "displayName": "Tran Nhat Anh", "familyName": "Anh", "givenName": "Tran Nhat", "displayNameLastFirst": "Anh, Tran Nhat"}], "coverPhotos": [{"metadata": {"primary": true, "source": {"type": "PROFILE", "id": "116622784508820350508"}}, "url": "https://lh3.googleusercontent.com/c5dqxl-2uHZ82ah9p7yxrVF1ZssrJNSV_15Nu0TUZwzCWqmtoLxCUJgEzLGtxsrJ6-v6R6rKU_-FYm881TTiMCJ_=s1600", "default": true}], "photos": [{"metadata": {"primary": true, "source": {"type": "PROFILE", "id": "116622784508820350508"}}, "url": "https://lh3.googleusercontent.com/-p4jH3cZmMQA/AAAAAAAAAAI/AAAAAAAAAAA/AGDgw-iogXifcIDzJjkHzXg-ChUwNDkkSQ/s100/photo.jpg", "default": true}], "emailAddresses": [{"metadata": {"primary": true, "verified": true, "source": {"type": "ACCOUNT", "id": "116622784508820350508"}}, "value": "anhtnbk2810@gmail.com"}]}
"""


def _normalize_google_attribute(key, value):
    meta = value['metadata']
    del value['metadata']
    value['source_type'] = meta['source']['type']
    if 'primary' in meta:
        value['primary'] = meta['primary']
    if 'verified' in meta:
        value['verified'] = meta['verified']
    if key == 'birthdays':
        date = value['date']
        if 'year' in date:
            value['date'] = '{}/{}'.format(date['month'], date['day'])
        else:
            value['date'] = '{}/{}/{}'.format(date['year'], date['month'], date['day'])
    return value


import json
response = json.loads(profile)
print(response)

rs_name = response['resourceName']
user_id = rs_name.split('/')[1]
del response['resourceName']
del response['etag']
attrs = dict()
for key, values in response.items():
    norm_values = [_normalize_google_attribute(key, v) for v in values]
    attrs[key] = norm_values

print(user_id, json.dumps(attrs))
