import urllib.parse as up
from datetime import datetime, timedelta
import time

import requests
from flask import request, url_for
import jwt

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    UnsupportedProviderError, NotFoundError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import gen_random_token, get_remote_ip, add_params_to_uri, calculate_hmac


__PROVIDER_SETTINGS__ = {
    'line': {
        'authorize_uri': 'https://access.line.me/oauth2/{version}/authorize?response_type=code',
        'token_uri': 'https://api.line.me/oauth2/{version}/token/',
        'profile_uri': 'https://api.line.me/v2/profile',
        'primary_attr': 'userId'
    },
    'yahoojp': {
        'authorize_uri': '''
            https://auth.login.yahoo.co.jp/yconnect/{version}/authorization?response_type=code
            &bail=1&display=page
            '''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://auth.login.yahoo.co.jp/yconnect/{version}/token',
        'profile_uri': 'https://userinfo.yahooapis.jp/yconnect/{version}/attribute',
        'primary_attr': 'sub'
    },
    'amazon': {
        'authorize_uri': '''
            https://apac.account.amazon.com/ap/oa?response_type=code
            &language=ja&ui_locales=&region=
            '''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'profile_uri': 'https://api.amazon.com/user/profile',
        'primary_attr': 'user_id'
    },
    'facebook': {
        'authorize_uri': 'https://www.facebook.com/{version}/dialog/oauth?response_type=code',
        'token_uri': 'https://graph.facebook.com/{version}/oauth/access_token',
        'profile_uri': 'https://graph.facebook.com/{version}/me',
        'primary_attr': 'id'
    },
    'twitter': {
        'request_token_uri': 'https://api.twitter.com/oauth/request_token',
        'authorize_uri': 'https://api.twitter.com/oauth/authenticate',
        'token_uri': 'https://api.twitter.com/oauth/access_token',
        'profile_uri': 'https://api.twitter.com/{version}/account/verify_credentials.json',
        'primary_attr': 'id_str'
    }
}

__DELIMITER__ = '|'


def get_backend(provider):
    if provider == 'line':
        return LineBackend(provider)
    elif provider == 'amazon':
        return AmazonBackend(provider)
    elif provider == 'yahoojp':
        return YahooJpBackend(provider)
    elif provider == 'facebook':
        return FacebookBackend(provider)
    elif provider == 'twitter':
        return TwitterBackend(provider)
    else:
        raise UnsupportedProviderError()


def is_valid_provider(provider):
    return provider in __PROVIDER_SETTINGS__


class OAuthBackend(object):
    JWT_TOKEN_ATTRIBUTE_NAME = 'id_token'
    OAUTH_VERSION = 2

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)

    def verify_request_success(self, query):
        if self.OAUTH_VERSION == 2:
            return 'code' in query
        else:
            return 'oauth_token' in query and 'oauth_verifier' in query

    def build_authorize_uri(self, app_id, succ_callback, fail_callback, **kwargs):
        """

        :param app_id:
        :param succ_callback:
        :param fail_callback:
        :param kwargs:
        :return:
        """
        app = Apps.query.filter_by(_id=app_id, _deleted=0).one_or_none()
        channel = Channels.query.filter_by(app_id=app_id,
                                           provider=self.provider).one_or_none()
        if not app or not channel:
            raise NotFoundError(msg='Application not found')

        allowed_uris = [up.unquote_plus(uri) for uri in app.callback_uris.split(__DELIMITER__)]
        logger.debug('Allowed URIs: {}. URI to verify: {}'
                     .format(allowed_uris, (succ_callback, fail_callback)))

        if not self._verify_callback_uri(allowed_uris, succ_callback):
            raise PermissionDeniedError(
                msg='Invalid callback_uri value. '
                    'Check if it is registered in EasyLogin developer site')
        if fail_callback and not self._verify_callback_uri(allowed_uris, fail_callback):
            raise PermissionDeniedError(
                msg='Invalid callback_if_failed value. '
                    'Check if it is registered in EasyLogin developer site')

        log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            ua=request.headers['User-Agent'],
            ip=get_remote_ip(request),
            nonce=gen_random_token(nbytes=32),
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(log)
        db.session.flush()

        if self.OAUTH_VERSION == 2:
            url = self._build_authorize_uri(
                channel=channel,
                state=log.generate_oauth_state(**kwargs))
            logger.debug('Authorize URL: %s', url)
        else:
            url, token, secret = self._build_oauth1_authorize_uri(
                channel=channel,
                state=log.generate_oauth_state(**kwargs))
            logger.debug('Authorize URL: %s', url)
            log.oa1_token = token
            log.oa1_secret = secret
        return url

    def handle_authorize_error(self, state, error, desc):
        """

        :param state:
        :param error:
        :param desc:
        :return:
        """
        log, args = self._verify_and_parse_state(state)
        log.status = AuthLogs.STATUS_FAILED
        fail_callback = log.callback_if_failed or log.callback_uri
        self._raise_redirect_error(error=error, msg=desc, fail_callback=fail_callback)

    def handle_authorize_success(self, state, query):
        """

        :param state:
        :param args:
        :return:
        """
        log, args = AuthLogs.parse_from_oauth_state(oauth_state=state)
        channel = Channels.query.filter_by(app_id=log.app_id,
                                           provider=self.provider).one_or_none()
        if self.OAUTH_VERSION == 2:
            code = query['code']
            profile = self.handle_oauth2_authorize_success(log, channel, code)
        else:
            profile = self.handle_oauth1_authorize_success(
                log=log, channel=channel,
                token=query['oauth_token'],
                verifier=query['oauth_verifier']
            )

        return profile, log, args

    def handle_oauth2_authorize_success(self, log, channel, code):
        """

        :param code:
        :return:
        """
        fail_callback = log.callback_if_failed or log.callback_uri
        tokens = self._get_token(channel, code, fail_callback)
        user_id, attrs = self._get_profile(channel, tokens, fail_callback)
        del attrs[self.__primary_attribute__()]

        try:
            profile, existed = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                scope_id=user_id, attrs=attrs)
            log.set_authorized(social_id=profile._id, is_login=existed,
                               nonce=gen_random_token(nbytes=32))
            token = Tokens(
                provider=self.provider,
                access_token=tokens['access_token'],
                token_type=tokens['token_type'],
                expires_at=datetime.utcnow() + timedelta(seconds=tokens['expires_in']),
                refresh_token=tokens.get('refresh_token'),
                jwt_token=tokens.get(self.JWT_TOKEN_ATTRIBUTE_NAME),
                social_id=profile._id
            )
            db.session.add(token)
            return profile
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def handle_oauth1_authorize_success(self, log, channel, token, verifier):
        """

        :param log:
        :param channel:
        :param token:
        :param verifier:
        :return:
        """
        fail_callback = log.callback_if_failed or log.callback_uri
        tokens = self._get_oauth1_token(
            channel=channel,
            tokens=(log.oa1_token, log.oa1_secret),
            verifier=verifier,
            fail_callback=fail_callback)
        user_id, attrs = self._get_oauth1_profile(
            channel=channel,
            tokens=tokens,
            fail_callback=fail_callback)
        del attrs[self.__primary_attribute__()]

        try:
            profile, existed = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                scope_id=user_id, attrs=attrs)
            log.set_authorized(social_id=profile._id, is_login=existed,
                               nonce=gen_random_token(nbytes=32))
            token = Tokens(
                provider=self.provider,
                token_type='OAuth',
                oa_version=Tokens.OA_VERSION_1A,
                oa1_token=tokens[0],
                oa1_secret=tokens[1],
                social_id=profile._id
            )
            db.session.add(token)
            return profile
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def _build_authorize_uri(self, channel, state):
        """

        :param channel:
        :param state:
        :return:
        """
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            client_id=channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=channel.permissions.replace(__DELIMITER__, ' '),
            state=state)
        return uri

    def _get_token(self, channel, code, fail_callback):
        """

        :param channel:
        :param code:
        :param fail_callback:
        :return:
        """
        res = requests.post(self.__token_uri__(version=channel.api_version), data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': channel.client_id,
            'client_secret': channel.client_secret
        })
        if res.status_code != 200:
            error, desc = self._get_error(res.json())
            self._raise_redirect_error(
                error=error,
                msg='Getting %s access token failed: %s' % (self.provider.upper(), desc),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, tokens, fail_callback):
        """

        :param channel:
        :param tokens:
        :param fail_callback:
        :return:
        """
        authorization = tokens['token_type'] + ' ' + tokens['access_token']
        res = requests.get(self.__profile_uri__(version=channel.api_version),
                           headers={'Authorization': authorization})
        if res.status_code != 200:
            error, desc = self._get_error(res.json())
            self._raise_redirect_error(
                error=error,
                msg='Getting %s profile failed: %s' % (self.provider.upper(), desc),
                fail_callback=fail_callback)

        return self._get_attributes(response=res.json(), channel=channel)

    def _get_attributes(self, channel, response):
        """

        :param response:
        :param channel:
        :return:
        """
        attrs = {}
        fields = (channel.required_fields or '').split(__DELIMITER__)
        for key, value in response.items():
            if key in fields or key == self.__primary_attribute__():
                attrs[key] = value
        return attrs[self.__primary_attribute__()], attrs

    def _build_oauth1_authorize_uri(self, channel, state):
        return None, None, None

    def _get_oauth1_token(self, channel, tokens, verifier, fail_callback):
        return None, None

    def _get_oauth1_profile(self, channel, tokens, fail_callback):
        return None, None

    def _get_error(self, response):
        return response['error'], response['error_description']

    def _raise_redirect_error(self, error, msg, fail_callback):
        raise RedirectLoginError(error=error, msg=msg,
                                 redirect_uri=fail_callback, provider=self.provider)

    def __primary_attribute__(self):
        return __PROVIDER_SETTINGS__[self.provider]['primary_attr']

    def __authorize_uri__(self, version=None, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return __PROVIDER_SETTINGS__[self.provider]['authorize_uri'].format(version=version)

    def __token_uri__(self, version=None, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return __PROVIDER_SETTINGS__[self.provider]['token_uri'].format(version=version)

    def __profile_uri__(self, version=None, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return __PROVIDER_SETTINGS__[self.provider]['profile_uri'].format(version=version)

    @staticmethod
    def _verify_and_parse_state(state):
        return AuthLogs.parse_from_oauth_state(oauth_state=state)

    @staticmethod
    def _verify_callback_uri(allowed_uris, uri):
        r1 = up.urlparse(uri)
        for _uri in allowed_uris:
            r2 = up.urlparse(_uri)
            ok = r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path
            if ok:
                return True
        return False


class LineBackend(OAuthBackend):
    """
    Authentication handler for LINE accounts
    """

    def _build_authorize_uri(self, channel, state):
        bot_prompt = ''
        options = (channel.options or '').split(__DELIMITER__)
        if 'add_friend' in options:
            bot_prompt = 'normal'

        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            bot_prompt=bot_prompt,
            nonce=gen_random_token(nbytes=16),
            client_id=channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=channel.permissions.replace(__DELIMITER__, ' '),
            state=state)
        return uri

    def _get_profile(self, channel, tokens, fail_callback):
        user_id, attrs = super()._get_profile(channel, tokens, fail_callback)
        try:
            payload = jwt.decode(tokens['id_token'],
                                 key=channel.client_secret,
                                 audience=channel.client_id,
                                 issuer='https://access.line.me',
                                 algorithms=['HS256'])
            if payload.get('email'):
                attrs['email'] = payload['email']
        except jwt.PyJWTError as e:
            logger.error(repr(e))
        return user_id, attrs


class AmazonBackend(OAuthBackend):
    """
    Authentication handler for AMAZON accounts
    """
    pass


class YahooJpBackend(OAuthBackend):
    """
    Authentication handler for YAHOOJP accounts
    """
    pass


class FacebookBackend(OAuthBackend):
    """
    Authentication handler for FACEBOOK accounts
    """

    def _get_token(self, channel, code, fail_callback):
        res = requests.get(self.__token_uri__(version=channel.api_version), params={
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': channel.client_id,
            'client_secret': channel.client_secret
        })
        if res.status_code != 200:
            error, desc = self._get_error(res.json())
            logger.debug('Getting access token failed: %s', repr(error))
            self._raise_redirect_error(
                error='OAuthException',
                msg='Getting %s access token failed: %s' % (self.provider.upper(), desc),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, tokens, fail_callback):
        fields = (channel.required_fields or '').split(__DELIMITER__)
        res = requests.get(self.__profile_uri__(version=channel.api_version), params={
            'fields': ','.join(fields),
            'access_token': tokens['access_token']
        })
        if res.status_code != 200:
            error, desc = self._get_error(res.json())
            logger.debug('Getting profile failed: %s', repr(error))
            self._raise_redirect_error(
                error='OAuthException',
                msg='Getting %s profile failed: %s' % (self.provider.upper(), desc),
                fail_callback=fail_callback)

        attrs = {}
        for key, value in res.json().items():
            attrs[key] = value
        return attrs[self.__primary_attribute__()], attrs

    def _get_error(self, response):
        return response['error'], response['error']['message']


class TwitterBackend(OAuthBackend):
    """
    Authentication handler for TWITTER accounts
    """
    OAUTH_VERSION = 1

    def _build_oauth1_authorize_uri(self, channel, state):
        request_token_uri = __PROVIDER_SETTINGS__[self.provider]['request_token_uri']
        callback_uri = add_params_to_uri(self.redirect_uri, state=state)
        auth = self.create_authorization_header(
            method='POST', 
            url=request_token_uri,
            consumer_key=channel.client_id,
            consumer_secret=channel.client_secret,
            oauth_callback=callback_uri)

        res = requests.post(request_token_uri, headers={'Authorization': auth})
        if res.status_code != 200:
            logger.debug('Getting request token failed, status code: %d', res.status_code)

        body = up.parse_qs(res.text)
        if not body.get('oauth_callback_confirmed'):
            pass

        token = body['oauth_token'][0]
        secret = body['oauth_token_secret'][0]
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            oauth_token=token)
        return uri, token, secret

    def _get_oauth1_token(self, channel, tokens, verifier, fail_callback):
        token_uri = self.__token_uri__(version=channel.api_version)
        auth = self.create_authorization_header(
            method='POST', 
            url=token_uri,
            consumer_key=channel.client_id,
            consumer_secret=channel.client_secret,
            oauth_token_secret=tokens[1],
            oauth_token=tokens[0]
        )
        res = requests.post(token_uri, headers={'Authorization': auth},
                            data={'oauth_verifier': verifier})
        if res.status_code != 200:
            logger.debug('Getting access token failed, status code: %d', res.status_code)
        body = up.parse_qs(res.text)
        return body['oauth_token'][0], body['oauth_token_secret'][0]

    def _get_oauth1_profile(self, channel, tokens, fail_callback):
        profile_uri = self.__profile_uri__(version=channel.api_version, numeric_format=True)
        auth = self.create_authorization_header(
            method='GET',
            url=profile_uri,
            consumer_key=channel.client_id,
            consumer_secret=channel.client_secret,
            oauth_token_secret=tokens[1],
            oauth_token=tokens[0],
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
            logger.debug('Getting profile failed, status code: %d', res.status_code)
            raise PermissionDeniedError()
        return self._get_attributes(channel, res.json())

    def _get_error(self, response):
        pass

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
        sign_base = '{}&{}&{}'.format(method, up.quote(url, safe=''), up.quote(param, safe=''))
        sign_key = up.quote(consumer_secret) + '&' + up.quote(oauth_token_secret)

        return calculate_hmac(key=sign_key, raw=sign_base)
