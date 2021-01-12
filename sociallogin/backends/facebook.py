import requests

from sociallogin import logger
from sociallogin.backends import OAuthBackend


class FacebookBackend(OAuthBackend):
    """
    Authentication handler for FACEBOOK accounts
    """
    AUTHORIZE_URI = 'https://www.facebook.com/{version}/dialog/oauth?response_type=code'
    TOKEN_URI = 'https://graph.facebook.com/{version}/oauth/access_token'
    VERIFY_TOKEN_URI = 'https://graph.facebook.com/{version}/debug_token'
    PROFILE_URI = 'https://graph.facebook.com/{version}/me'
    IDENTIFY_ATTRS = ['id']

    def _get_token(self, code):
        res = requests.get(self.__token_uri__(version=self.channel.api_version), params={
            'code': code,
            'redirect_uri': self.__provider_callback_uri__(),
            'client_id': self.channel.client_id,
            'client_secret': self.channel.client_secret
        })
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed',
                        provider=self.provider.upper(), **body)
            self._raise_error(error=self.ERROR_GET_TOKEN_FAILED,
                              msg='{}: {}'.format(error, desc))
        return res.json()

    def _get_profile(self, tokens):
        fields = self.channel.get_required_fields()
        res = requests.get(self.__profile_uri__(version=self.channel.api_version), params={
            'fields': ','.join(fields),
            'access_token': tokens['access_token']
        })
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._get_attributes(response=res.json(), nofilter=True)

    def _get_error(self, response, action):
        if action != 'authorize':
            return response['error']['type'], response['error']['message']
        else:
            return super()._get_error(response, action)
