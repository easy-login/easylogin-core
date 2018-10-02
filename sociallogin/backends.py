import urllib.parse as urlparse
from datetime import datetime, timedelta

import requests
from flask import request, url_for
import jwt

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    UnsupportedProviderError, NotFoundError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import gen_random_token, get_remote_ip, add_params_to_uri


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
        'refresh_token_uri': '',
        'profile_uri': 'https://graph.facebook.com/{version}/me?fields={fields}',
        'primary_attr': 'id'
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
    else:
        raise UnsupportedProviderError()


def is_valid_provider(provider):
    return provider in __PROVIDER_SETTINGS__


class OAuthBackend(object):

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)

    def build_authorize_uri(self, app_id, succ_callback, fail_callback, **kwargs):
        app = Apps.query.filter_by(_id=app_id).one_or_none()
        channel = Channels.query.filter_by(app_id=app_id,
                                           provider=self.provider).one_or_none()
        if not app or not channel:
            raise NotFoundError(msg='Application not found')

        allowed_uris = [urlparse.unquote_plus(uri) for uri in app.callback_uris.split(__DELIMITER__)]
        logger.debug('Allowed URIs: {}. URI to verify: {}'
                     .format(allowed_uris, (succ_callback, fail_callback)))

        if not self._verify_callback_uri(allowed_uris, succ_callback):
            raise PermissionDeniedError(msg='Callback URI must be configured in admin settings')
        if fail_callback and not self._verify_callback_uri(allowed_uris, fail_callback):
            raise PermissionDeniedError(msg='Callback URI must be configured in admin settings')

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

        url = self._build_authorize_uri(
            channel=channel,
            state=log.generate_oauth_state(**kwargs),
            redirect_uri=self.redirect_uri)
        logger.debug('Authorize URL: %s', url)
        return url

    def handle_authorize_error(self, state, error, desc):
        log, args = self._verify_and_parse_state(state)
        log.status = AuthLogs.STATUS_FAILED
        fail_callback = log.callback_if_failed or log.callback_uri
        self._raise_redirect_error(error=error, msg=desc, fail_callback=fail_callback)

    def handle_authorize_success(self, state, code):
        log, args = self._verify_and_parse_state(state)
        fail_callback = log.callback_if_failed or log.callback_uri

        channel = Channels.query.filter_by(app_id=log.app_id,
                                           provider=self.provider).one_or_none()
        tokens = self._get_token(channel, code, fail_callback)
        user_id, attrs = self._get_profile(channel, tokens, fail_callback)
        try:
            profile, existed = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                pk=user_id, attrs=attrs)
            log.set_authorized(social_id=profile._id, is_login=existed,
                               nonce=gen_random_token(nbytes=32))
            token = Tokens(
                provider=self.provider,
                access_token=tokens['access_token'],
                token_type=tokens['token_type'],
                expires_at=datetime.utcnow() + timedelta(seconds=tokens['expires_in']),
                refresh_token=tokens.get('refresh_token'),
                jwt_token=self._extract_jwt_token(tokens),
                social_id=profile._id
            )
            db.session.add(token)
            return profile, log, args
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def _build_authorize_uri(self, channel, redirect_uri, state):
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            client_id=channel.client_id,
            redirect_uri=redirect_uri,
            scope=channel.permissions.replace(__DELIMITER__, ' '),
            state=state)
        return uri

    def _get_token(self, channel, code, fail_callback):
        res = requests.post(self.__token_uri__(version=channel.api_version), data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': channel.client_id,
            'client_secret': channel.client_secret
        })
        if res.status_code != 200:
            error = res.json()
            self._raise_redirect_error(
                error=error['error'],
                msg='Getting %s access token failed: %s' % (self.provider.upper(),
                                                            error['error_description']),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, tokens, fail_callback):
        auth_header = tokens['token_type'] + ' ' + tokens['access_token']
        res = requests.get(self.__profile_uri__(version=channel.api_version),
                           headers={'Authorization': auth_header})
        if res.status_code != 200:
            print(res)
            error = res.json()
            self._raise_redirect_error(
                error=error['error'],
                msg='Getting %s profile failed: %s' % (self.provider.upper(),
                                                       error['error_description']),
                fail_callback=fail_callback)

        attrs = {}
        fields = (channel.required_fields or '').split(__DELIMITER__)
        for key, value in res.json().items():
            if key in fields or key == self.__primary_attribute__():
                attrs[key] = value
        return attrs[self.__primary_attribute__()], attrs

    def _extract_jwt_token(self, body):
        return body.get('id_token')

    def _raise_redirect_error(self, error, msg, fail_callback):
        raise RedirectLoginError(error=error, msg=msg,
                                 redirect_uri=fail_callback, provider=self.provider)

    def __primary_attribute__(self):
        return __PROVIDER_SETTINGS__[self.provider]['primary_attr']

    def __authorize_uri__(self, version):
        return __PROVIDER_SETTINGS__[self.provider]['authorize_uri'].format(version=version)

    def __token_uri__(self, version):
        return __PROVIDER_SETTINGS__[self.provider]['token_uri'].format(version=version)

    def __profile_uri__(self, version):
        return __PROVIDER_SETTINGS__[self.provider]['profile_uri'].format(version=version)

    @staticmethod
    def _verify_and_parse_state(state):
        return AuthLogs.parse_from_oauth_state(oauth_state=state)

    @staticmethod
    def _verify_callback_uri(allowed_uris, uri):
        r1 = urlparse.urlparse(uri)
        for _uri in allowed_uris:
            r2 = urlparse.urlparse(_uri)
            ok = r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path
            if ok:
                return True
        return False


class LineBackend(OAuthBackend):
    """
    Authentication handler for LINE accounts
    """
    def _build_authorize_uri(self, channel, redirect_uri, state):
        bot_prompt = ''
        options = (channel.options or '').split(__DELIMITER__)
        if 'add_friend' in options:
            bot_prompt = 'normal'

        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=channel.api_version),
            bot_prompt=bot_prompt,
            nonce=gen_random_token(nbytes=48),
            client_id=channel.client_id,
            redirect_uri=redirect_uri,
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
            error = res.json()
            self._raise_redirect_error(
                error=error['error'],
                msg='Getting %s access token failed: %s' % (self.provider.upper(),
                                                            error['error_description']),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, tokens, fail_callback):
        auth_header = tokens['token_type'] + ' ' + tokens['access_token']
        fields = (channel.required_fields or '').split(__DELIMITER__)

        res = requests.get(self.__profile_uri__(version=channel.api_version),
                           params={'fields': ','.join(fields)},
                           headers={'Authorization': auth_header})
        if res.status_code != 200:
            error = res.json()
            self._raise_redirect_error(
                error=error['error'],
                msg='Getting %s profile failed: %s' % (self.provider.upper(),
                                                       error['error_description']),
                fail_callback=fail_callback)

        attrs = {}
        for key, value in res.json().items():
            attrs[key] = value
        return attrs[self.__primary_attribute__()], attrs
