import pickle
import time
from urllib import parse as urlparse
import hashlib
import jwt
import msgpack

from sociallogin.exc import TokenParseError
from sociallogin.utils import calculate_hmac, base64encode, base64decode
from sociallogin import app, logger


class EasyTokenService:
    """
    First version, use Pickle to serialize/deserialize
    """
    PREFIX = 'ESLG'

    def __init__(self, key):
        self.key = key

    def generate(self, sub, exp_in_seconds, **kwargs):
        now = int(time.time())
        payload = {
            'sub': sub,
            'exp': now + exp_in_seconds,
            'data': kwargs
        }
        raw = urlparse.urlencode(payload)
        sign = calculate_hmac(self.key, raw, digestmod=hashlib.sha256)
        payload['sign'] = sign

        token = base64encode(self.serialize(raw=payload), urlsafe=True, padding=False)
        return self.PREFIX + token

    def decode(self, token):
        try:
            data = base64decode(token[4:], urlsafe=True)
            payload = self.deserialize(packed=data)
            sign = payload['sign']
            del payload['sign']
            raw = urlparse.urlencode(payload)
            expected_sign = calculate_hmac(self.key, raw, digestmod=hashlib.sha256)

            if sign != expected_sign:
                msg = 'Invalid signature, expected sign: {}, actual sign: {}'
                raise TokenParseError(msg.format(expected_sign, sign, token))
            if payload['exp'] < int(time.time()):
                raise TokenParseError('Token expired')
            return payload['sub'], payload['data']
        except TokenParseError:
            raise
        except Exception as e:
            logger.debug('Decode easy token error', error=str(e))
            raise TokenParseError('Token malformed')

    @classmethod
    def serialize(cls, raw):
        return pickle.dumps(raw)

    @classmethod
    def deserialize(cls, packed):
        return pickle.loads(packed)


class EasyTokenService2(EasyTokenService):
    """
    Second version, use message packe to serialize/deserialize
    """

    @classmethod
    def serialize(cls, raw):
        return msgpack.packb(raw, use_bin_type=True)

    @classmethod
    def deserialize(cls, packed):
        return msgpack.unpackb(packed, raw=False)


class JwtTokenService:
    def __init__(self, key, issuer=None):
        self.key = key
        self.issuer = issuer

    def generate(self, sub, exp_in_seconds, **kwargs):
        now = int(time.time())
        return jwt.encode({
            'iss': self.issuer,
            'sub': sub,
            'exp': now + exp_in_seconds,
            'iat': now,
            'data': kwargs
        }, key=self.key, algorithm='HS256').decode('utf8')

    def decode(self, token):
        try:
            payload = jwt.decode(token, key=self.key, issuer=self.issuer,
                                 algorithms=['HS256'])
            if int(payload['exp']) < int(time.time()):
                raise TokenParseError('Token expired')
            return payload['sub'], payload['data']
        except TokenParseError:
            raise
        except Exception as e:
            logger.debug('Decore JWT token error', error=str(e))
            raise TokenParseError('Token malformed')


# Define default TokenService object
jwt_token_service = JwtTokenService(key=app.config['SECRET_KEY'], issuer='easy-login.jp')
easy_token_service = EasyTokenService2(key=app.config['SECRET_KEY'])
