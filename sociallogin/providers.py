import urllib.parse as urlparse
from datetime import datetime, timedelta

import requests
from flask import request, abort, url_for
import jwt

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import gen_random_token, get_remote_ip


__PROVIDER_SETTINGS__ = {
    'line': {
        'authorize_uri': '''
            https://access.line.me/oauth2/{api_version}/authorize?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &bot_prompt=normal
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.line.me/oauth2/v2.1/token/',
        'profile_uri': 'https://api.line.me/v2/profile',
        'primary_attr': 'userId'
    },
    'yahoojp': {
        'authorize_uri': '''
            https://auth.login.yahoo.co.jp/yconnect/{api_version}/authorization?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &bail=1&display=page
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://auth.login.yahoo.co.jp/yconnect/v2/token',
        'profile_uri': 'https://userinfo.yahooapis.jp/yconnect/v2/attribute',
        'primary_attr': 'sub'
    },
    'amazon': {
        'authorize_uri': '''
            https://www.amazon.com/ap/oa?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'profile_uri': 'https://api.amazon.com/user/profile',
        'primary_attr': 'user_id'
    }
}

__SPLITOR__ = '|'


def get_auth_handler(provider):
    if provider == 'line':
        return LineAuthHandler(provider)
    elif provider == 'amazon':
        return AmazonAuthHandler(provider)
    elif provider == 'yahoojp':
        return YahooJpAuthHandler(provider)
    else: 
        return abort(404, 'Unsupported provider')


def is_valid_provider(provider):
    return provider in __PROVIDER_SETTINGS__


class ProviderAuthHandler(object):

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)
    
    def build_authorize_uri(self, app_id, succ_callback, fail_callback, **kwargs):
        app = Apps.query.filter_by(_id=app_id).one_or_none()
        channel = Channels.query.filter_by(app_id=app_id,
                                           provider=self.provider).one_or_none()
        if not app or not channel:
            abort(404, 'Application not found')

        allowed_uris = [urlparse.unquote_plus(uri) for uri in app.callback_uris.split(__SPLITOR__)]
        logger.debug('Allowed URIs: {}. URI to verify: {}'
                     .format(allowed_uris, (succ_callback, fail_callback)))

        if not self._verify_callback_uri(allowed_uris, succ_callback):
            abort(403, 'Callback URI must be configured in admin settings')
        if fail_callback and not self._verify_callback_uri(allowed_uris, fail_callback):
            abort(403, 'Callback URI must be configured in admin settings')

        nonce = gen_random_token(nbytes=32)
        log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            ua=request.headers['User-Agent'],
            ip=get_remote_ip(request),
            nonce=nonce,
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(log)
        db.session.flush()

        return self._build_authorize_uri(
            channel=channel, 
            state=log.generate_oauth_state(**kwargs),
            redirect_uri=urlparse.quote_plus(self.redirect_uri))

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
        token_dict = self._get_token(channel, code, fail_callback)
        pk, attrs = self._get_profile(channel, token_dict, fail_callback)
        try:
            profile, existed = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                pk=pk, attrs=attrs)
            log.set_authorized(social_id=profile._id, is_login=existed,
                               nonce=gen_random_token(nbytes=32))
            token = Tokens(
                provider=self.provider,
                access_token=token_dict['access_token'],
                token_type=token_dict['token_type'],
                expires_at=datetime.utcnow() + timedelta(seconds=token_dict['expires_in']),
                refresh_token=token_dict['refresh_token'],
                jwt_token=self._extract_jwt_token(token_dict),
                social_id=profile._id
            )
            db.session.add(token)
            return profile, log, args
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def _build_authorize_uri(self, channel, redirect_uri, state):
        url = self.__authorize_uri__().format(
            api_version=channel.api_version,
            client_id=channel.client_id,
            redirect_uri=redirect_uri,
            scope=urlparse.quote(channel.permissions.replace(__SPLITOR__, ' ')),
            state=state)
        return url

    def _get_token(self, channel, code, fail_callback):
        res = requests.post(self.__token_uri__(), data={
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
                msg='Getting %s access token failed: %s' % (self.provider.upper(), error['error_description']),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, channel, token_dict, fail_callback):
        auth_header = token_dict['token_type'] + ' ' + token_dict['access_token']
        res = requests.get(self.__profile_uri__(), headers={'Authorization': auth_header})
        if res.status_code != 200:
            error = res.json()
            self._raise_redirect_error(
                error=error['error'], 
                msg='Getting %s profile failed: %s' % (self.provider.upper(), error['error_description']),
                fail_callback=fail_callback)

        attrs = {}
        fields = (channel.required_fields or '').split(__SPLITOR__)
        for key, value in res.json().items():
            if key in fields or key == self.__primary_attribute__():
                attrs[key] = value
        return attrs[self.__primary_attribute__()], attrs

    def _extract_jwt_token(self, token_dict):
        return token_dict.get('id_token')

    def _raise_redirect_error(self, error, msg, fail_callback):
        raise RedirectLoginError(error=error, msg=msg, 
                                 redirect_uri=fail_callback, provider=self.provider)

    def __primary_attribute__(self):
        return __PROVIDER_SETTINGS__[self.provider]['primary_attr']

    def __authorize_uri__(self):
        return __PROVIDER_SETTINGS__[self.provider]['authorize_uri']

    def __token_uri__(self):
        return __PROVIDER_SETTINGS__[self.provider]['token_uri']

    def __profile_uri__(self):
        return __PROVIDER_SETTINGS__[self.provider]['profile_uri']

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


class LineAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for LINE accounts
    """
    def _build_authorize_uri(self, channel, redirect_uri, state):
        bot_prompt = ''
        options = (channel.options or '').split(__SPLITOR__)
        if 'add_friend' in options:
            bot_prompt = 'normal'

        url = self.__authorize_uri__().format(
            api_version=channel.api_version,
            bot_prompt=bot_prompt,
            client_id=channel.client_id,
            redirect_uri=redirect_uri,
            scope=urlparse.quote(channel.permissions.replace(__SPLITOR__, ' ')),
            state=state)
        return url

    def _get_profile(self, channel, token_dict, fail_callback):
        pk, attrs = super()._get_profile(channel, token_dict, fail_callback)
        try:
            payload = jwt.decode(token_dict['id_token'],
                                 key=channel.client_secret,
                                 audience=channel.client_id,
                                 issuer='https://access.line.me',
                                 algorithms=['HS256'])
            if payload.get('email'):
                attrs['email'] = payload['email']
        except jwt.PyJWTError as e:
            logger.error(repr(e))
        return pk, attrs


class AmazonAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for AMAZON accounts
    """
    pass


class YahooJpAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for YAHOOJP accounts
    """
    pass