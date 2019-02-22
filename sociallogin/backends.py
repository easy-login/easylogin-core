import urllib.parse as up
from datetime import datetime, timedelta
import time
import json

import requests
import jwt
from flask import request, url_for, make_response, redirect, jsonify

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    UnsupportedProviderError, NotFoundError, BadRequestError, TokenParseError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, \
    SocialProfiles, JournalLogs, AssociateLogs
from sociallogin.utils import gen_random_token, add_params_to_uri, \
    calculate_hmac, smart_str2bool, unix_time_millis, get_remote_ip, update_dict

__PROVIDER_SETTINGS__ = {
    'line': {
        'authorize_uri': 'https://access.line.me/oauth2/{version}/authorize?response_type=code',
        'token_uri': 'https://api.line.me/oauth2/{version}/token/',
        'profile_uri': 'https://api.line.me/v2/profile',
        'verify_token_uri': 'https://api.line.me/oauth2/{version}/verify',
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
        'authorize_uri': 'https://apac.account.amazon.com/ap/oa?response_type=code',
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'verify_token_uri': 'https://api.amazon.com/auth/o2/tokeninfo',
        'profile_uri': 'https://api.amazon.com/user/profile',
        'identify_attrs': ['user_id']
    },
    'amazon_sandbox': {
        'authorize_uri': 'https://apac.account.amazon.com/ap/oa?response_type=code&sandbox=true',
        'token_uri': 'https://api.sandbox.amazon.com/auth/o2/token',
        'verify_token_uri': 'https://api.amazon.com/auth/o2/tokeninfo',
        'profile_uri': 'https://api.sandbox.amazon.com/user/profile'
    },
    'facebook': {
        'authorize_uri': 'https://www.facebook.com/{version}/dialog/oauth?response_type=code',
        'token_uri': 'https://graph.facebook.com/{version}/oauth/access_token',
        'verify_token_uri': 'https://graph.facebook.com/{version}/debug_token',
        'profile_uri': 'https://graph.facebook.com/{version}/me',
        'identify_attrs': ['id']
    },
    'twitter': {
        'request_token_uri': 'https://api.twitter.com/oauth/request_token',
        'authorize_uri': 'https://api.twitter.com/oauth/authenticate',
        'token_uri': 'https://api.twitter.com/oauth/access_token',
        'profile_uri': 'https://api.twitter.com/{version}/account/verify_credentials.json',
        'identify_attrs': ['id_str', 'id']
    },
    'google': {
        'authorize_uri': '''
            https://accounts.google.com/o/oauth2/v2/auth?response_type=code
            &prompt=select_account&login_hint=sub&include_granted_scopes=true&access_type=offline
            '''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://www.googleapis.com/oauth2/v4/token',
        'verify_token_uri': 'https://www.googleapis.com/oauth2/v3/tokeninfo',
        'profile_uri': 'https://people.googleapis.com/{version}/people/me',
        'identify_attrs': ['sub']
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
    elif provider == 'google':
        return GoogleBackend(provider)
    else:
        raise UnsupportedProviderError()


def is_valid_provider(provider):
    return provider in __PROVIDER_SETTINGS__


class OAuthBackend(object):
    OAUTH_VERSION = 2
    SANDBOX_SUPPORT = False
    OPENID_CONNECT_SUPPORT = False

    ERROR_AUTHORIZE_FAILED = 'authorize_failed'
    ERROR_GET_TOKEN_FAILED = 'get_token_failed'
    ERROR_GET_PROFILE_FAILED = 'get_profile_failed'

    def __init__(self, provider):
        self.provider = provider
        self.sandbox = False
        self.platform = None

        self.channel = None
        self.log = None
        self.token = None
        self.profile = None
        self.args = None

    def verify_callback_success(self, params):
        if self.OAUTH_VERSION == 2:
            return 'code' in params
        else:
            return 'oauth_token' in params and 'oauth_verifier' in params

    def authorize(self, app_id, intent, succ_callback, fail_callback, params):
        """

        :param app_id:
        :param intent:
        :param succ_callback:
        :param fail_callback:
        :param params:
        :return:
        """
        # Verify request params and extract extra args
        self._init_authorize(intent=intent, params=params)

        app = Apps.query.filter_by(_id=app_id, _deleted=0).one_or_none()
        self.channel = Channels.query.filter_by(app_id=app_id,
                                                provider=self.provider).one_or_none()
        if not app or not self.channel:
            raise NotFoundError(msg='Application or channel not found')

        if not self._is_mobile():
            allowed_uris = [up.unquote_plus(uri) for uri in app.get_callback_uris()]
            logger.debug('Verify callback URI', style='hybrid', allowed_uris=allowed_uris,
                         succ_callback=succ_callback, fail_callback=fail_callback)

            illegal_callback_msg = ('Invalid callback_uri value. '
                                    'Check if it is registered in EasyLogin developer site')
            if not self.verify_callback_uri(allowed_uris, succ_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)
            if fail_callback and not self.verify_callback_uri(allowed_uris, fail_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)

        self.log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            nonce=gen_random_token(nbytes=32),
            intent=intent,
            platform=self.platform,
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(self.log)
        db.session.flush()
        db.session.add(JournalLogs(
            ua=request.headers.get('User-Agent'),
            ip=get_remote_ip(request),
            path=request.full_path,
            ref_id=self.log._id
        ))

        oauth_state = self.log.generate_oauth_state(**self.args)
        if self._is_mobile():
            return jsonify({
                'channel': {
                    'client_id': self.channel.client_id,
                    'options': self.channel.get_options(),
                    'scopes': self.channel.get_permissions()
                },
                'state': oauth_state
            })
        else:
            url = self._build_authorize_uri(state=oauth_state)
            logger.debug('Authorize URL', url)
            return redirect(url)

    def _init_authorize(self, intent, params):
        self.sandbox = smart_str2bool(params.get('sandbox'))
        if self.sandbox:
            self._enable_sandbox()

        nonce = params.get('nonce', '')
        if len(nonce) > 255:
            raise BadRequestError('Nonce length exceeded limit 255 characters')

        self.platform = params.get('platform', 'web')
        if self.platform not in ['web', 'ios', 'and']:
            raise BadRequestError('Invalid or unsupported platform')

        self.args = {
            'sandbox': self.sandbox,
            'platform': self.platform,
            'nonce': nonce
        }
        if self._is_mobile():
            code_challenge = params.get('code_challenge', '')
            if not code_challenge:
                raise BadRequestError('Missing required parameter code_challenge for mobile client')
            if len(code_challenge) != 64:
                raise BadRequestError('Malformed parameter: code_challenge')
            self.args['code_challenge'] = code_challenge

        if intent == AuthLogs.INTENT_ASSOCIATE:
            assoc_token = params.get('associate_token', '')
            try:
                alog = AssociateLogs.parse_associate_token(assoc_token)
                if alog.provider != self.provider:
                    raise BadRequestError('Invalid target provider, must be {}'.format(alog.provider))

                alog.status = AssociateLogs.STATUS_AUTHORIZING
                update_dict(self.args, dst_social_id=alog.dst_social_id, provider=self.provider)
            except TokenParseError as e:
                logger.warning('Parse associate token failed',
                               error=e.description, token=assoc_token)
                raise BadRequestError('Invalid associate token')
        elif intent == AuthLogs.INTENT_PAY_WITH_AMAZON:
            update_dict(self.args, lpwa_domain=params.get('site_domain'))

    def _is_mobile(self):
        return self.platform != 'web'

    def _build_authorize_uri(self, state):
        """

        :param state:
        :return:
        """
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            client_id=self.channel.client_id,
            redirect_uri=self.__provider_callback_uri__(),
            scope=up.unquote_plus(self.channel.get_perms_as_oauth_scope()),
            state=state)
        if self.OPENID_CONNECT_SUPPORT:
            uri += '&nonce=' + gen_random_token(nbytes=16, format='hex')
        return uri

    def handle_authorize_error(self, state, params):
        """

        :param state:
        :param params:
        :return:
        """
        self.log, self.args = self.verify_and_parse_state(state)
        self.log.status = AuthLogs.STATUS_FAILED
        if self.log.provider != self.provider:
            raise PermissionDeniedError('OAuth state invalid, provider does not match',
                                        provider=self.log.provider, expected=self.provider)

        error, desc = self._get_error(params, action='authorize')
        logger.debug('Authorize failed', provider=self.provider.upper(),
                     error=error, message=desc)
        self._raise_error(error=self.ERROR_AUTHORIZE_FAILED,
                          msg='{}, {}'.format(error, desc))

    def handle_authorize_success(self, state, params):
        """

        :param state:
        :param params:
        :return:
        """
        self.log, self.args = self.verify_and_parse_state(state)
        if self.log.provider != self.provider:
            logger.warn('Provider in OAuth state does not match with current provider',
                        provider=self.log.provider, expected=self.provider)
            raise PermissionDeniedError('OAuth state invalid, provider does not match')

        if self.args.get('sandbox'):
            self._enable_sandbox()
        self.platform = self.args.get('platform')
        logger.debug('Parse OAuth state result', sub=self.log._id, **self.args)

        self.channel = Channels.query.filter_by(app_id=self.log.app_id,
                                                provider=self.provider).one_or_none()
        try:
            self.profile, self.token = self._handle_authentication(params)
        except Exception:
            self.log.status = AuthLogs.STATUS_FAILED
            db.session.commit()
            raise

        intent = self.log.intent
        if intent == AuthLogs.INTENT_ASSOCIATE:
            if self.args.get('provider') != self.provider:
                self._raise_error(error='permission_denied',
                                  msg='Target provider does not match')
            elif self.profile.user_id:
                self._raise_error(error='conflict',
                                  msg='Profile has linked with another user')
            self.profile.merge_with(alias=self.args.get('dst_social_id'))
        elif intent == AuthLogs.INTENT_LOGIN and not self.log.is_login:
            self._raise_error(
                error='invalid_request',
                msg='Social profile does not exist, should register instead'
            )
        elif intent == AuthLogs.INTENT_REGISTER and self.log.is_login:
            self._raise_error(
                error='invalid_request',
                msg='Social profile already existed, should login instead'
            )

        if self._is_mobile():
            auth_token = self.log.generate_auth_token(
                code_challenge=self.args.get('code_challenge'))
            return jsonify({
                'auth_token': auth_token,
                'expires_in': 3900
            })
        else:
            auth_token = self.log.generate_auth_token()
            callback_uri = add_params_to_uri(
                uri=self.log.callback_uri,
                provider=self.provider,
                token=auth_token,
                nonce=self.args.get('nonce', '')
            )
            return self._make_redirect_response(callback_uri=callback_uri)

    def _handle_authentication(self, params):
        """

        :param params:
        :return:
        """
        if self._is_mobile():
            access_token = params['access_token']
            id_token = params.get('id_token')
            tokens = self._debug_token(access_token=access_token, id_token=id_token)
        else:
            code = params['code']
            tokens = self._get_token(code=code)
        user_id, attrs = self._get_profile(tokens=tokens)

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
            jwt_token=tokens.get('id_token'),
            social_id=profile._id
        )
        db.session.add(token)
        return profile, token

    def _enable_sandbox(self):
        if self.SANDBOX_SUPPORT:
            self.sandbox = True
            logger.info('Enable sandbox mode', provider=self.provider)
        else:
            logger.warn('Cannot enable sandbox mode, provider is not supported',
                        provider=self.provider)

    def _get_token(self, code):
        """

        :param code:
        :return:
        """
        res = requests.post(self.__token_uri__(version=self.channel.api_version), data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.__provider_callback_uri__(),
            'client_id': self.channel.client_id,
            'client_secret': self.channel.client_secret
        })
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(error=self.ERROR_GET_TOKEN_FAILED,
                              msg='{}: {}'.format(error, desc))
        return res.json()

    def _debug_token(self, access_token, id_token=None):
        """

        :param access_token:
        :return:
        """
        res = requests.get(self.__verify_token_uri(version=self.channel.api_version),
                           params={'access_token': access_token})
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Verify access token failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(error=self.ERROR_GET_TOKEN_FAILED,
                              msg='{}: {}'.format(error, desc))
        token_info = res.json()
        client_id = token_info['client_id']
        if client_id != self.channel.client_id:
            logger.warn('Access token does not belong to current app',
                        client_id=client_id, expected=self.channel.client_id)
            raise PermissionDeniedError('Illegal access token')
        return {
            'access_token': access_token,
            'expires_in': token_info['expires_in'],
            'token_type': 'Bearer',
            'id_token': id_token
        }

    def _get_profile(self, tokens):
        """

        :param tokens:
        :return:
        """
        authorization = tokens['token_type'] + ' ' + tokens['access_token']
        res = requests.get(self.__profile_uri__(version=self.channel.api_version),
                           headers={'Authorization': authorization})
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._get_attributes(response=res.json())

    def _get_attributes(self, response, nofilter=False):
        """

        :param response:
        :param nofilter:
        :return:
        """
        user_id = response[self.__identify_attrs__()[0]]
        if nofilter or self.channel.option_enabled(key='extra_fields'):
            for key in self.__identify_attrs__():
                del response[key]
            return user_id, response

        attrs = dict()
        fields = self.channel.get_required_fields()
        for key, value in response.items():
            if key in fields:
                attrs[key] = value
        return user_id, attrs

    def _make_redirect_response(self, callback_uri):
        """
        Make response redirect to client callback URI
        :param callback_uri:
        :return:
        """
        return redirect(callback_uri)

    def _get_error(self, response, action):
        return response['error'], response.get('error_description', '')

    def _raise_error(self, error, msg):
        if self._is_mobile():
            return jsonify({
                'error': error,
                'error_description': msg,
                'provider': self.provider
            })
        else:
            raise RedirectLoginError(
                error=error, msg=msg,
                nonce=self.args.get('nonce', ''),
                redirect_uri=self.log.get_failed_callback(),
                provider=self.provider)

    def __identify_attrs__(self):
        return __PROVIDER_SETTINGS__[self.provider]['identify_attrs']

    def __authorize_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        key = self.provider + '_sandbox' if self.sandbox else self.provider
        return __PROVIDER_SETTINGS__[key]['authorize_uri'].format(version=version)

    def __token_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        key = self.provider + '_sandbox' if self.sandbox else self.provider
        return __PROVIDER_SETTINGS__[key]['token_uri'].format(version=version)

    def __verify_token_uri(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        key = self.provider + '_sandbox' if self.sandbox else self.provider
        return __PROVIDER_SETTINGS__[key]['verify_token_uri'].format(version=version)

    def __profile_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        key = self.provider + '_sandbox' if self.sandbox else self.provider
        return __PROVIDER_SETTINGS__[key]['profile_uri'].format(version=version)

    def __provider_callback_uri__(self):
        return url_for('authorize_callback', _external=True, provider=self.provider)

    @staticmethod
    def verify_and_parse_state(state):
        try:
            return AuthLogs.parse_oauth_state(oauth_state=state)
        except TokenParseError as e:
            logger.warning('Parse OAuth state failed', error=e.description, token=state)
            raise BadRequestError('Invalid OAuth state')

    @staticmethod
    def verify_callback_uri(allowed_uris, uri):
        if not uri:
            return False
        r1 = up.urlparse(uri)
        # Always allow callback for hosted JS
        if r1.netloc == 'api.easy-login.jp' \
                and r1.path == '/hosted/auth/callback' \
                and r1.scheme == 'https':
            return True

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
    OPENID_CONNECT_SUPPORT = True

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


class AmazonBackend(OAuthBackend):
    """
    Authentication handler for AMAZON accounts
    """
    SANDBOX_SUPPORT = True

    def _build_authorize_uri(self, state):
        amz_pay_enabled = self.channel.option_enabled('amazon_pay')
        if amz_pay_enabled:
            scope = self._perms_for_pay()
        else:
            scope = self.channel.get_perms_as_oauth_scope()
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            client_id=self.channel.client_id,
            redirect_uri=self.__provider_callback_uri__(),
            scope=scope,
            state=state)
        return uri

    def _make_redirect_response(self, callback_uri):
        amz_pay_enabled = self.channel.option_enabled('amazon_pay')
        if not amz_pay_enabled or self.log.intent != AuthLogs.INTENT_PAY_WITH_AMAZON:
            return super()._make_redirect_response(callback_uri)

        cookie_object = {
            "access_token": self.token.access_token,
            "max_age": 3300,
            "expiration_date": unix_time_millis(self.token.expires_at),
            "client_id": self.channel.client_id,
            "scope": self._perms_for_pay()
        }
        resp = make_response(redirect(callback_uri))
        domain = self.args.get('lpwa_domain') or self.extract_domain_for_cookie(callback_uri)
        resp.set_cookie(key='amazon_Login_state_cache',
                        value=up.quote(json.dumps(cookie_object), safe=''),
                        domain=domain, expires=None, max_age=None)
        resp.set_cookie(key='amazon_Login_accessToken',
                        value=self.token.access_token,
                        domain=domain, expires=None, max_age=3300)
        logger.debug('Set cookie for amazon pay', domain=domain or 'localhost')
        return resp

    def _perms_for_pay(self):
        return self.channel.get_perms_as_oauth_scope() \
               + ' payments:widget payments:shipping_address'


class YahooJpBackend(OAuthBackend):
    """
    Authentication handler for YAHOOJP accounts
    """
    OPENID_CONNECT_SUPPORT = True

    def _get_error(self, response, action):
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


class TwitterBackend(OAuthBackend):
    """
    Authentication handler for TWITTER accounts
    """
    OAUTH_VERSION = 1

    def _build_authorize_uri(self, state):
        request_token_uri = __PROVIDER_SETTINGS__[self.provider]['request_token_uri']
        callback_uri = add_params_to_uri(self.__provider_callback_uri__(), state=state)
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

    def _handle_authentication(self, params):
        """

        :param params:
        :return:
        """
        oauth_verifier = params['oauth_verifier']
        tokens = self._get_token(oauth_verifier)
        user_id, attrs = self._get_profile(tokens=tokens)

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

    def _get_token(self, oauth_verifier):
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

    def _get_profile(self, tokens):
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
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting profile failed')

        return self._get_attributes(response=res.json())

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


class GoogleBackend(OAuthBackend):
    """
    Authentication handler for GOOGLE accounts
    """
    OPENID_CONNECT_SUPPORT = True

    def _get_profile(self, tokens):
        perms = self.channel.get_permissions()
        fields = self.channel.get_required_fields()
        if 'email' in perms and 'emailAddresses' not in fields:
            fields.append('emailAddresses')
        fields.remove('#')
        res = requests.get(self.__profile_uri__(version=self.channel.api_version), params={
            'personFields': ','.join(fields),
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

    def _get_attributes(self, response, nofilter=False):
        rs_name = response['resourceName']
        user_id = rs_name.split('/')[1]
        attrs = dict()
        for key, values in response.items():
            if type(values) != list:
                continue
            norm_values = [self._normalize_google_attribute(key, v) for v in values]
            attrs[key] = norm_values
        return user_id, attrs

    @staticmethod
    def _normalize_google_attribute(key, value):
        meta = value['metadata']
        value['source_type'] = meta['source']['type']
        if 'primary' in meta:
            value['primary'] = meta['primary']
        if 'verified' in meta:
            value['verified'] = meta['verified']
        if key == 'birthdays':
            date = value['date']
            if 'year' in date:
                value['date'] = '{}/{}/{}'.format(date['year'], date['month'], date['day'])
            else:
                value['date'] = '{}/{}'.format(date['month'], date['day'])
        del value['metadata']
        return value
