import time
import urllib.parse as up
from typing import Dict, Any, Tuple

import requests

from sociallogin import db, logger
from sociallogin.backends import OAuthBackend
from sociallogin.entities import OAuthCallbackParams, OAuthSessionParams
from sociallogin.models import Tokens, \
    SocialProfiles, AuthLogs
from sociallogin.utils import gen_random_token, add_params_to_uri, \
    calculate_hmac


class TwitterBackend(OAuthBackend):
    """
    Authentication handler for TWITTER accounts
    """
    OAUTH_VERSION = 1

    REQUEST_TOKEN_URI = 'https://api.twitter.com/oauth/request_token'
    AUTHORIZE_URI = 'https://api.twitter.com/oauth/authenticate'
    TOKEN_URI = 'https://api.twitter.com/oauth/access_token'
    PROFILE_URI = 'https://api.twitter.com/{version}/account/verify_credentials.json'
    IDENTIFY_ATTRS = ['id_str', 'id']

    def _build_authorize_uri(self, state):
        callback_uri = add_params_to_uri(self.__provider_callback_uri__(), state=state)
        auth = self.create_authorization_header(
            method='POST',
            url=self.REQUEST_TOKEN_URI,
            consumer_key=self.channel.client_id,
            consumer_secret=self.channel.client_secret,
            oauth_callback=callback_uri)

        res = requests.post(self.REQUEST_TOKEN_URI, headers={'Authorization': auth})
        if res.status_code != 200:
            body = up.parse_qs(res.text)
            logger.warn('Getting request token failed', code=res.status_code, **body)
            self._raise_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed')

        body = up.parse_qs(res.text)
        if not body['oauth_callback_confirmed'][0]:
            logger.warn('Getting request token failed', oauth_callback_confirmed=0)
            self._raise_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed: oauth_callback_confirmed=false')

        token = body['oauth_token'][0]
        secret = body['oauth_token_secret'][0]
        self.log.oa1_token = token
        self.log.oa1_secret = secret

        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            oauth_token=token)
        return uri

    def _handle_authentication(self, params: OAuthCallbackParams) -> Tuple[SocialProfiles, Tokens]:
        """
        Handle authentication, return authenticated profile + token info
        :param params:
        :return:
        """
        oauth_verifier = params.oauth_verifier
        token_tup = self._get_token_oa1(oauth_verifier)
        user_id, attrs = self._get_profile_oa1(token_tup=token_tup)

        profile, existed = SocialProfiles.add_or_update(
            app_id=self.log.app_id,
            provider=self.provider,
            scope_id=user_id, attrs=attrs)
        self.log.set_authorized(social_id=profile._id, is_login=existed,
                                nonce=gen_random_token(nbytes=32))
        token = Tokens(
            provider=self.provider,
            token_type='OAuth',
            oa_version=Tokens.OA_VERSION_1A,
            oa1_token=token_tup[0],
            oa1_secret=token_tup[1],
            social_id=profile._id
        )
        db.session.add(token)
        return profile, token

    def _get_token_oa1(self, oauth_verifier: str) -> Tuple[str, str]:
        token_uri = self.__token_uri__(version=self.channel.api_version)
        auth = self.create_authorization_header(
            method='POST',
            url=token_uri,
            consumer_key=self.channel.client_id,
            consumer_secret=self.channel.client_secret,
            oauth_token_secret=self.log.oa1_secret,
            oauth_token=self.log.oa1_token
        )
        res = requests.post(token_uri, headers={'Authorization': auth},
                            data={'oauth_verifier': oauth_verifier})
        if res.status_code != 200:
            body = up.parse_qs(res.text)
            logger.warn('Getting access token failed', code=res.status_code, **body)
            self._raise_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting access token failed')

        body = up.parse_qs(res.text)
        return body['oauth_token'][0], body['oauth_token_secret'][0]

    def _get_profile_oa1(self, token_tup: Tuple[str, str]) -> Tuple[str, Dict[str, Any]]:
        profile_uri = self.__profile_uri__(version=self.channel.api_version, numeric_format=True)
        auth = self.create_authorization_header(
            method='GET',
            url=profile_uri,
            consumer_key=self.channel.client_id,
            consumer_secret=self.channel.client_secret,
            oauth_token_secret=token_tup[1],
            oauth_token=token_tup[0],
            include_entities='false',
            skip_status='true',
            include_email='true'
        )
        res = requests.get(profile_uri, headers={'Authorization': auth}, params={
            'include_entities': 'false',
            'skip_status': 'true',
            'include_email': 'true'
        })
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', code=res.status_code, **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting profile failed')

        return self._parse_attributes(response=res.json())

    def _get_error(self, response, action):
        if action != 'authorize':
            return response['code'][0], response['message'][0]
        else:
            return super()._get_error(response, action)

    @classmethod
    def create_authorization_header(cls, method, url, consumer_key, consumer_secret,
                                    oauth_token_secret='', **kwargs):
        auth = {
            'oauth_consumer_key': consumer_key,
            'oauth_nonce': gen_random_token(nbytes=16, format='hex'),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_version': '1.0'
        }
        sign = cls.create_signature(method, url, auth, consumer_secret,
                                    oauth_token_secret, **kwargs)
        for k, v in kwargs.items():
            if k.startswith('oauth_'):
                auth[k] = v
        auth['oauth_signature'] = sign
        authorization = ', '.join(['{}="{}"'.format(k, up.quote(v, safe=''))
                                   for k, v in auth.items()])
        return 'OAuth ' + authorization

    @classmethod
    def create_signature(cls, method, url, auth, consumer_secret,
                         oauth_token_secret='', **kwargs):
        kwargs.update(auth)
        sorted_keys = sorted(kwargs)
        param = '&'.join([k + '=' + up.quote(kwargs[k], safe='') for k in sorted_keys])
        sign_base = '{method}&{base_url}&{param}'.format(
            method=method,
            base_url=up.quote(url, safe=''),
            param=up.quote(param, safe=''))
        sign_key = up.quote(consumer_secret) + '&' + up.quote(oauth_token_secret)
        return calculate_hmac(key=sign_key, raw=sign_base, output_format='base64')
