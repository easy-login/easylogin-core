import base64
import hashlib
import hmac
import requests
from urllib import parse as up
import secrets
import time
import json

# key = CONSUMER_SECRET& #If you dont have a token yet
key = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"

# The Base String as specified here:
raw = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%25"  # as specified by oauth


def hmac_sha1(key, raw):
    hashed = hmac.new(key.encode('ascii'), raw.encode('ascii'), hashlib.sha1)
    return base64.standard_b64encode(hashed.digest()).decode('ascii').rstrip('\n')


# The signature
# sign = hmac_sha1(key, raw)
# print(sign)


def create_signature(method, url, auth, consumer_secret, token_secret='', **kwargs):
    kwargs.update(auth)
    sorted_keys = sorted(kwargs)
    param = '&'.join([k + '=' + up.quote(kwargs[k], safe='') for k in sorted_keys])
    sign_base = '{}&{}&{}'.format(method, up.quote(url, safe=''), up.quote(param, safe=''))
    sign_key = up.quote(consumer_secret) + '&' + up.quote(token_secret)

    return hmac_sha1(key=sign_key, raw=sign_base)


# api_url = 'https://api.twitter.com/oauth/request_token'
# callback_url = 'http://localhost:5000/authorize/twitter/approval_state'

# api_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
api_url = 'https://api.twitter.com/1.1/users/show.json'

consumer_key = 'oIIWIrLjOWS2vGoGrUPK5LGRa'
consumer_secret = 'DMt2cdkIe369f7bHj8VRnxvdkGP6NXekrQvWhd2tDYeDUW93Hp'
# token = '599165668-bDEPMswkECWTZrLPYVB0zQJtvsntZQSQJtVCUMbt'
# token_secret = 'vRUxQJW8dHG9opO0cpbxlDIOnK5WR9STxCqmGb6xNhLsB'
token = '599165668-bDEPMswkECWTZrLPYVB0zQJtvsntZQSQJtVCUMbt'
token_secret = 'vRUxQJW8dHG9opO0cpbxlDIOnK5WR9STxCqmGb6xNhLsB'

auth = {
    'oauth_consumer_key': consumer_key,
    'oauth_nonce': secrets.token_hex(nbytes=16),
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_timestamp': str(int(time.time())),
    'oauth_version': '1.0',
    'oauth_token': token
}
sign = create_signature(
    method='GET', url=api_url,
    auth=auth,
    consumer_secret=consumer_secret,
    token_secret=token_secret,
    screen_name='boybka_dhn',
    skip_status='true',
    # include_email='true',
    include_entities='false',
)
auth['oauth_signature'] = sign
# auth['oauth_callback'] = callback_url

authorization = ', '.join(['{}="{}"'.format(k, up.quote(v, safe='')) for k, v in auth.items()])
print('authorization', authorization)

r = requests.get(api_url, headers={'Authorization': 'OAuth ' + authorization}, params={
    'screen_name': 'boybka_dhn',
    'include_entities': 'false',
    'skip_status': 'true',
    # 'include_email': 'true'
})
print(r.status_code)
print(json.dumps(dict(r.headers), indent=2))
# print(up.parse_qs(r.text))

attrs = r.json()
text = json.dumps(r.json(), indent=2)
print(text, len(text))
