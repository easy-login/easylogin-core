import urllib.parse as up
from datetime import datetime, timedelta
import time

import requests
from flask import request, url_for
import jwt

from sociallogin import db, logger, get_remote_ip
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    UnsupportedProviderError, NotFoundError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import gen_random_token, add_params_to_uri, calculate_hmac


__PROVIDER_SETTINGS__ = {
    'line': {
        'authorize_uri': 'https://access.line.me/oauth2/{version}/authorize?response_type=code',
        'token_uri': 'https://api.line.me/oauth2/{version}/token/',
        'profile_uri': 'https://api.line.me/v2/profile',
        'identify_attrs': ['userId']
    },
    'yahoojp': {
        'authorize_uri': '''
            https://auth.login.yahoo.co.jp/yconnect/{version}/authorization?response_type=code
            &bail=1&display=page
            '''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://auth.login.yahoo.co.jp/yconnect/{version}/token',
        'profile_uri': 'https://userinfo.yahooapis.jp/yconnect/{version}/attribute',
        'identify_attrs': ['sub']
    },
    'amazon': {
        'authorize_uri': '''
            https://apac.account.amazon.com/ap/oa?response_type=code
            &language=ja&ui_locales=&region=
            '''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'profile_uri': 'https://api.amazon.com/user/profile',
        'identify_attrs': ['user_id']
    },
    'facebook': {
        'authorize_uri': 'https://www.facebook.com/{version}/dialog/oauth?response_type=code',
        'token_uri': 'https://graph.facebook.com/{version}/oauth/access_token',
        'profile_uri': 'https://graph.facebook.com/{version}/me',
        'identify_attrs': ['id']
    },
    'twitter': {
        'request_token_uri': 'https://api.twitter.com/oauth/request_token',
        'authorize_uri': 'https://api.twitter.com/oauth/authenticate',
        'token_uri': 'https://api.twitter.com/oauth/access_token',
        'profile_uri': 'https://api.twitter.com/{version}/account/verify_credentials.json',
        'identify_attrs': ['id_str', 'id']
    }
}


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

    ERROR_AUTHORIZE_FAILED = 'authorize_failed'
    ERROR_GET_TOKEN_FAILED = 'get_token_failed'
    ERROR_GET_PROFILE_FAILED = 'get_profile_failed'

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)

    def verify_request_success(self, qs):
        if self.OAUTH_VERSION == 2:
            return 'code' in qs
        else:
            return 'oauth_token' in qs and 'oauth_verifier' in qs

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

        allowed_uris = [up.unquote_plus(uri) for uri in app.get_callback_uris()]
        logger.debug('Verify callback URI', style='hybrid', allowed_uris=allowed_uris, 
                     succ_callback=succ_callback, fail_callback=fail_callback)

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
            logger.debug('Authorize URL', url)
        else:
            url, token, secret = self._build_oauth1_authorize_uri(
                channel=channel,
                fail_callback=log.get_failed_callback(),
                state=log.generate_oauth_state(**kwargs))
            logger.debug('Authorize URL', url)
            log.oa1_token = token
            log.oa1_secret = secret
        return url

    def handle_authorize_error(self, state, qs):
        """

        :param state:
        :param qs:
        :return:
        """
        log, args = self._verify_and_parse_state(state)
        log.status = AuthLogs.STATUS_FAILED
        fail_callback = log.get_failed_callback()

        error, desc = self._get_error(qs)
        logger.debug('Authorize failed', provider=self.provider.upper(), 
                     error=error, message=desc)
        self._raise_redirect_error(
            error=self.ERROR_AUTHORIZE_FAILED, 
            msg='{}: {}'.format(error, desc), 
            fail_callback=fail_callback)

    def handle_authorize_success(self, state, qs):
        """

        :param state:
        :param qs:
        :return:
        """
        log, args = self._verify_and_parse_state(state)
        channel = Channels.query.filter_by(app_id=log.app_id,
                                           provider=self.provider).one_or_none()
        if self.OAUTH_VERSION == 2:
            code = qs['code']
            profile = self.handle_oauth2_authorize_success(log, channel, code)
        else:
            profile = self.handle_oauth1_authorize_success(
                log=log, channel=channel,
                token=qs['oauth_token'],
                verifier=qs['oauth_verifier']
            )
        return profile, log, args

    def handle_oauth2_authorize_success(self, log, channel, code):
        """

        :param code:
        :return:
        """
        fail_callback = log.get_failed_callback()
        tokens = self._get_token(channel, code, fail_callback)
        user_id, attrs = self._get_profile(channel, tokens, fail_callback)

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
        fail_callback = log.get_failed_callback()
        tokens = self._get_oauth1_token(
            channel=channel,
            tokens=(log.oa1_token, log.oa1_secret),
            verifier=verifier,
            fail_callback=fail_callback)
        user_id, attrs = self._get_oauth1_profile(
            channel=channel,
            tokens=tokens,
            fail_callback=fail_callback)

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
            scope=channel.get_perms_as_oauth_scope(),
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
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed', 
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='{}: {}'.format(error, desc),
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
            body = res.json()
            logger.warn('Getting profile failed', 
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed',
                fail_callback=fail_callback)

        return self._get_attributes(response=res.json(), channel=channel)

    def _get_attributes(self, channel, response, nofilter=False):
        """

        :param response:
        :param channel:
        :param nofilter:
        :return:
        """
        user_id = response[self.__identify_attrs__()[0]]
        if nofilter or channel.extra_fields_enabled():
            for key in self.__identify_attrs__():
                del response[key]
            return user_id, response
            
        attrs = dict()
        fields = channel.get_required_fields()
        for key, value in response.items():
            if key in fields:
                attrs[key] = value
        return user_id, attrs

    def _build_oauth1_authorize_uri(self, channel, state, fail_callback):
        raise NotImplementedError()

    def _get_oauth1_token(self, channel, tokens, verifier, fail_callback):
        raise NotImplementedError()

    def _get_oauth1_profile(self, channel, tokens, fail_callback):
        raise NotImplementedError()

    def _get_error(self, response, action='authorize'):
        return response['error'], response['error_description']

    def _raise_redirect_error(self, error, msg, fail_callback):
        raise RedirectLoginError(error=error, msg=msg,
                                 redirect_uri=fail_callback, provider=self.provider)

    def __identify_attrs__(self):
        return __PROVIDER_SETTINGS__[self.provider]['identify_attrs']

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
        if not uri:
            return False
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
        if 'add_friend' in channel.get_options():
            bot_prompt = 'normal'

        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            bot_prompt=bot_prompt,
            nonce=gen_random_token(nbytes=16),
            client_id=channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=channel.get_perms_as_oauth_scope(),
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
    
    def _get_error(self, response, action='authorize'):
        if action == 'get_profile':
            return 'api_error', response['message']
        else:
            return super()._get_error(response, action)


class AmazonBackend(OAuthBackend):
    """
    Authentication handler for AMAZON accounts
    """
    def _build_authorize_uri(self, channel, state):
        scope = channel.get_perms_as_oauth_scope()
        if 'amazon_pay' in channel.get_options():
            scope += ' payments:widget payments:shipping_address payments:billing_address'
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            client_id=channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=scope, state=state)
        return uri


class YahooJpBackend(OAuthBackend):
    """
    Authentication handler for YAHOOJP accounts
    """
    def _get_error(self, response, action='authorize'):
        if action == 'get_profile':
            return 'api_error', response['Error']['Message']
        else:
            return super()._get_error(response, action)


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
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed', 
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='{}: {}'.format(error, desc),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, tokens, fail_callback):
        fields = channel.get_required_fields()
        res = requests.get(self.__profile_uri__(version=channel.api_version), params={
            'fields': ','.join(fields),
            'access_token': tokens['access_token']
        })
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed',
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed',
                fail_callback=fail_callback)

        return self._get_attributes(channel=channel, response=res.json(), nofilter=True)

    def _get_error(self, response, action='authorize'):
        if action != 'authorize':
            return response['error']['type'], response['error']['message']
        else:
            return super()._get_error(response, action)


class TwitterBackend(OAuthBackend):
    """
    Authentication handler for TWITTER accounts
    """
    OAUTH_VERSION = 1

    def _build_oauth1_authorize_uri(self, channel, state, fail_callback):
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
            body = up.parse_qs(res.text)
            logger.warn('Getting request token failed', code=res.status_code, **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed',
                fail_callback=fail_callback)

        body = up.parse_qs(res.text)
        if not body['oauth_callback_confirmed'][0]:
            logger.warn('Getting request token failed', oauth_callback_confirmed=0)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed: oauth_callback_confirmed=false',
                fail_callback=fail_callback)

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
            body = up.parse_qs(res.text)
            logger.warn('Getting access token failed', code=res.status_code, **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting access token failed',
                fail_callback=fail_callback)

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
            body = res.json()
            logger.warn('Getting profile failed', code=res.status_code, **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting profile failed',
                fail_callback=fail_callback)

        return self._get_attributes(channel, res.json())

    def _get_error(self, response, action='authorize'):
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

        return calculate_hmac(key=sign_key, raw=sign_base)
