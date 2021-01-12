import jwt

from sociallogin import logger
from sociallogin.backends import OAuthBackend


class LineBackend(OAuthBackend):
    """
    Authentication handler for LINE accounts
    """
    OPENID_CONNECT_SUPPORT = True

    AUTHORIZE_URI = 'https://access.line.me/oauth2/{version}/authorize?response_type=code'
    TOKEN_URI = 'https://api.line.me/oauth2/{version}/token/'
    VERIFY_TOKEN_URI = 'https://api.line.me/oauth2/{version}/verify'
    PROFILE_URI = 'https://api.line.me/v2/profile'
    IDENTIFY_ATTRS = ['userId']

    def _build_authorize_uri(self, state):
        uri = super()._build_authorize_uri(state)
        if self.channel.option_enabled('add_friend'):
            uri += '&bot_prompt=aggressive'
        return uri

    def _get_profile(self, tokens):
        user_id, attrs = super()._get_profile(tokens)
        try:
            payload = jwt.decode(tokens['id_token'],
                                 key=self.channel.client_secret,
                                 audience=self.channel.client_id,
                                 issuer='https://access.line.me',
                                 algorithms=['HS256'])
            if payload.get('email'):
                attrs['email'] = payload['email']
        except (jwt.PyJWTError, KeyError) as e:
            logger.error(repr(e))
        return user_id, attrs

    def _get_error(self, response, action):
        if action == 'get_profile':
            return 'api_error', response['message']
        else:
            return super()._get_error(response, action)
