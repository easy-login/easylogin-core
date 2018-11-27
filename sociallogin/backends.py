import urllib.parse as up
from datetime import datetime, timedelta
import time
import json

import requests
import jwt
from flask import request, url_for, make_response, redirect

from sociallogin import db, logger, get_remote_ip
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    UnsupportedProviderError, NotFoundError, BadRequestError, TokenParseError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import gen_random_token, add_params_to_uri, calculate_hmac, \
    smart_str2bool, unix_time_millis

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
    'amazon_sandbox': {
        'authorize_uri': 'https://www.amazon.com/ap/oa?response_type=code&sandbox=true',
        'token_uri': 'https://api.sandbox.amazon.com/auth/o2/token',
        'profile_uri': 'https://api.sandbox.amazon.com/user/profile'
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


def get_backend(provider, sandbox=False):
    if provider == 'line':
        return LineBackend(provider, sandbox)
    elif provider == 'amazon':
        return AmazonBackend(provider, sandbox)
    elif provider == 'yahoojp':
        return YahooJpBackend(provider, sandbox)
    elif provider == 'facebook':
        return FacebookBackend(provider, sandbox)
    elif provider == 'twitter':
        return TwitterBackend(provider, sandbox)
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

    def __init__(self, provider, sandbox):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)
        self.sandbox = sandbox
        self.channel = None
        self.log = None
        self.token = None
        self.profile = None
        self.args = None

    def verify_callback_success(self, qs):
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
        self.channel = Channels.query.filter_by(app_id=app_id,
                                                provider=self.provider).one_or_none()
        if not app or not self.channel:
            raise NotFoundError(msg='Application or channel not found')

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

        self.log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            ua=request.headers['User-Agent'],
            ip=get_remote_ip(request),
            nonce=gen_random_token(nbytes=32),
            intent=kwargs.get('intent'),
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(self.log)
        db.session.flush()

        if self.OAUTH_VERSION == 2:
            url = self._build_authorize_uri(state=self.log.generate_oauth_state(**kwargs))
            logger.debug('Authorize URL', url)
        else:
            url, oa1_token, oa1_secret = self._build_oauth1_authorize_uri(
                state=self.log.generate_oauth_state(**kwargs))
            self.log.oa1_token = oa1_token
            self.log.oa1_secret = oa1_secret
        logger.debug('Authorize URL', url)
        return url

    def handle_authorize_error(self, state, qs):
        """

        :param state:
        :param qs:
        :return:
        """
        self.log, self.args = self._verify_and_parse_state(state)
        self.log.status = AuthLogs.STATUS_FAILED

        error, desc = self._get_error(qs)
        logger.info('Authorize failed', provider=self.provider.upper(),
                    error=error, message=desc)
        self._raise_redirect_error(
            error=self.ERROR_AUTHORIZE_FAILED,
            msg='{}, {}'.format(error, desc))

    def handle_authorize_success(self, state, qs):
        """

        :param state:
        :param qs:
        :return:
        """
        self.log, self.args = self._verify_and_parse_state(state)
        if smart_str2bool(self.args.get('sandbox')):
            self.sandbox = True
            logger.debug('Handle auth callback in sandbox mode', provider=self.provider)

        self.channel = Channels.query.filter_by(app_id=self.log.app_id,
                                                provider=self.provider).one_or_none()
        if self.OAUTH_VERSION == 2:
            self.profile, self.token = self.handle_oauth2_authorize_success(qs)
        else:
            self.profile, self.token = self.handle_oauth1_authorize_success(qs)

        intent = self.args.get('intent')
        if intent == AuthLogs.INTENT_ASSOCIATE:
            if self.args.get('provider') != self.provider:
                self._raise_redirect_error(error='permission_denied',
                                           msg='Target provider does not match')
            elif self.profile.user_id:
                self._raise_redirect_error(error='conflict',
                                           msg='Profile has linked with another user')
                self.profile.link_user_by_id(user_id=self.args.get('user_id'))
        elif intent == AuthLogs.INTENT_LOGIN and not self.log.is_login:
            self._raise_redirect_error(
                error='invalid_request',
                msg='Social profile does not exist, should register instead')
        elif intent == AuthLogs.INTENT_REGISTER and self.log.is_login:
            self._raise_redirect_error(
                error='invalid_request',
                msg='Social profile already existed, should login instead')

        auth_token = self.log.generate_auth_token()
        callback_uri = add_params_to_uri(
            uri=self.log.callback_uri,
            provider=self.provider,
            token=auth_token,
            nonce=self.args.get('nonce'),
            profile_uri=url_for('authorized_profile', _external=True,
                                app_id=self.log.app_id, token=auth_token)
        )
        return self._make_redirect_response(callback_uri=callback_uri)

    def handle_oauth2_authorize_success(self, qs):
        """

        :param log:
        :param channel:
        :param qs:
        :return:
        """
        code = qs['code']
        tokens = self._get_token(code=code)
        user_id, attrs = self._get_profile(tokens=tokens)
        try:
            profile, existed = SocialProfiles.add_or_update(
                app_id=self.log.app_id,
                provider=self.provider,
                scope_id=user_id, attrs=attrs)
            self.log.set_authorized(social_id=profile._id, is_login=existed,
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
            return profile, token
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def handle_oauth1_authorize_success(self, qs):
        """

        :param log:
        :param channel:
        :param qs:
        :return:
        """
        verifier = qs['oauth_verifier']
        tokens = self._get_oauth1_token(verifier=verifier)
        user_id, attrs = self._get_oauth1_profile(tokens=tokens)
        try:
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
                oa1_token=tokens[0],
                oa1_secret=tokens[1],
                social_id=profile._id
            )
            db.session.add(token)
            return profile, token
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def _build_authorize_uri(self, state):
        """

        :param channel:
        :param state:
        :return:
        """
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            client_id=self.channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.channel.get_perms_as_oauth_scope(),
            state=state)
        return uri

    def _get_token(self, code):
        """

        :param channel:
        :param code:
        :param fail_callback:
        :return:
        """
        res = requests.post(self.__token_uri__(version=self.channel.api_version), data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.channel.client_id,
            'client_secret': self.channel.client_secret
        })
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed',
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='{}: {}'.format(error, desc))
        return res.json()

    def _get_profile(self, tokens):
        """

        :param channel:
        :param tokens:
        :param fail_callback:
        :return:
        """
        authorization = tokens['token_type'] + ' ' + tokens['access_token']
        res = requests.get(self.__profile_uri__(version=self.channel.api_version),
                           headers={'Authorization': authorization})
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed',
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed',
                nonce=self.log.client_nonce,
                fail_callback=self.log.get_failed_callback())

        return self._get_attributes(response=res.json())

    def _get_attributes(self, response, nofilter=False):
        """

        :param response:
        :param channel:
        :param nofilter:
        :return:
        """
        user_id = response[self.__identify_attrs__()[0]]
        if nofilter or self.channel.option_enabled(key='extra_fields'):
            for key in self.__identify_attrs__():
                del response[key]
            return user_id, response

        attrs = dict()
        req_fields = self.channel.get_required_fields()
        for key, value in response.items():
            if key in req_fields:
                attrs[key] = value
        return user_id, attrs

    def _make_redirect_response(self, callback_uri):
        return redirect(callback_uri)

    def _build_oauth1_authorize_uri(self, state):
        raise NotImplementedError()

    def _get_oauth1_token(self, verifier):
        raise NotImplementedError()

    def _get_oauth1_profile(self, tokens):
        raise NotImplementedError()

    def _get_error(self, response, action='authorize'):
        return response['error'], response['error_description']

    def _raise_redirect_error(self, error, msg, **kwargs):
        raise RedirectLoginError(error=error, msg=msg,
                                 nonce=self.args.get('nonce'),
                                 redirect_uri=self.log.get_failed_callback(),
                                 provider=self.provider)

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
        try:
            return AuthLogs.parse_oauth_state(oauth_state=state)
        except TokenParseError as e:
            logger.warning('Parse OAuth state failed', error=e.description, token=state)
            raise BadRequestError('Invalid OAuth state. ' + e.description)

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

    @staticmethod
    def extract_domain_for_cookie(url, subdomain=True):
        netloc = up.urlparse(url).netloc
        if netloc.startswith('localhost'):
            return None
        else:
            parts = netloc.split('.')
            domain = parts[-2] + '.' + parts[-1]
            if subdomain:
                domain = '.' + domain
            return domain


class LineBackend(OAuthBackend):
    """
    Authentication handler for LINE accounts
    """

    def _build_authorize_uri(self, state):
        bot_prompt = ''
        if 'add_friend' in self.channel.get_options():
            bot_prompt = 'normal'

        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            bot_prompt=bot_prompt,
            nonce=gen_random_token(nbytes=16),
            client_id=self.channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.channel.get_perms_as_oauth_scope(),
            state=state)
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

    def _build_authorize_uri(self, state):
        amz_pay_enabled = self.channel.option_enabled('amazon_pay')
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            client_id=self.channel.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.channel.get_perms_as_oauth_scope(lpwa=amz_pay_enabled),
            state=state)
        return uri

    def _make_redirect_response(self, callback_uri):
        cookie_object = {
            "access_token": self.token.access_token,
            "max_age": 3300,
            "expiration_date": unix_time_millis(self.token.expires_at),
            "client_id": self.channel.client_id,
            "scope": self.channel.get_perms_as_oauth_scope(lpwa=True)
        }
        resp = make_response(redirect(callback_uri))
        domain = self.extract_domain_for_cookie(callback_uri)
        resp.set_cookie(key='amazon_Login_state_cache',
                        value=up.quote(json.dumps(cookie_object), safe=''),
                        domain=domain,
                        expires=None, max_age=3300)
        logger.debug('Set cookie for amazon pay', domain=domain)
        return resp

    def __authorize_uri__(self, version=None, numeric_format=False):
        if self.sandbox:
            return __PROVIDER_SETTINGS__['amazon_sandbox']['authorize_uri']
        else:
            return super().__authorize_uri__(version, numeric_format)

    def __token_uri__(self, version=None, numeric_format=False):
        if self.sandbox:
            return __PROVIDER_SETTINGS__['amazon_sandbox']['token_uri']
        else:
            return super().__token_uri__(version, numeric_format)

    def __profile_uri__(self, version=None, numeric_format=False):
        if self.sandbox:
            return __PROVIDER_SETTINGS__['amazon_sandbox']['profile_uri']
        else:
            return super().__profile_uri__(version, numeric_format)


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

    def _get_token(self, code):
        res = requests.get(self.__token_uri__(version=self.channel.api_version), params={
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.channel.client_id,
            'client_secret': self.channel.client_secret
        })
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed',
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(error=self.ERROR_GET_TOKEN_FAILED,
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
            logger.warn('Getting profile failed',
                        provider=self.provider.upper(), **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._get_attributes(response=res.json(), nofilter=True)

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

    def _build_oauth1_authorize_uri(self, state):
        request_token_uri = __PROVIDER_SETTINGS__[self.provider]['request_token_uri']
        callback_uri = add_params_to_uri(self.redirect_uri, state=state)
        auth = self.create_authorization_header(
            method='POST',
            url=request_token_uri,
            consumer_key=self.channel.client_id,
            consumer_secret=self.channel.client_secret,
            oauth_callback=callback_uri)

        res = requests.post(request_token_uri, headers={'Authorization': auth})
        if res.status_code != 200:
            body = up.parse_qs(res.text)
            logger.warn('Getting request token failed', code=res.status_code, **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed')

        body = up.parse_qs(res.text)
        if not body['oauth_callback_confirmed'][0]:
            logger.warn('Getting request token failed', oauth_callback_confirmed=0)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting request token failed: oauth_callback_confirmed=false')

        token = body['oauth_token'][0]
        secret = body['oauth_token_secret'][0]
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            oauth_token=token)
        return uri, token, secret

    def _get_oauth1_token(self, verifier):
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
                            data={'oauth_verifier': verifier})
        if res.status_code != 200:
            body = up.parse_qs(res.text)
            logger.warn('Getting access token failed', code=res.status_code, **body)
            self._raise_redirect_error(
                error=self.ERROR_GET_TOKEN_FAILED,
                msg='Getting access token failed')

        body = up.parse_qs(res.text)
        return body['oauth_token'][0], body['oauth_token_secret'][0]

    def _get_oauth1_profile(self, tokens):
        profile_uri = self.__profile_uri__(version=self.channel.api_version, numeric_format=True)
        auth = self.create_authorization_header(
            method='GET',
            url=profile_uri,
            consumer_key=self.channel.client_id,
            consumer_secret=self.channel.client_secret,
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
                msg='Getting profile failed')

        return self._get_attributes(response=res.json())

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
