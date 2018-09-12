import urllib.parse as urlparse
from datetime import datetime, timedelta

import requests
from flask import request, abort, url_for

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles, AssociateLogs
from sociallogin.utils import gen_random_token, add_params_to_uri

__END_POINTS__ = {
    'line': {
        'authorize_uri': '''
            https://access.line.me/oauth2/v2.1/authorize?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.line.me/oauth2/v2.1/token/',
        'profile_uri': 'https://api.line.me/v2/profile'
    },
    'yahoojp': {
        'authorize_uri': '''
            https://auth.login.yahoo.co.jp/yconnect/v2/authorization?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &bail=1&max_age=600&display=page&prompt=login
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://auth.login.yahoo.co.jp/yconnect/v2/token',
        'profile_uri': 'https://userinfo.yahooapis.jp/yconnect/v2/attribute'
    },
    'amazon': {
        'authorize_uri': '''
            https://www.amazon.com/ap/oa?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'profile_uri': 'https://api.amazon.com/user/profile'
    }
}


__PROVIDERS__ = ['line', 'amazon', 'yahoojp']


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
    return provider in __PROVIDERS__


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

        allowed_uris = [urlparse.unquote_plus(uri) for uri in app.callback_uris.split('|')]
        logger.debug('Allowed URIs: {}. URI to verify: {}'
                     .format(allowed_uris, (succ_callback, fail_callback)))

        if not self._verify_callback_uri(allowed_uris, succ_callback):
            abort(403, 'Callback URI must be configured in admin settings')
        if fail_callback and not self._verify_callback_uri(allowed_uris, fail_callback):
            abort(403, 'Callback URI must be configured in admin settings')

        nonce = gen_random_token(nbytes=16)
        log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            ua=request.headers['User-Agent'],
            ip=request.remote_addr,
            nonce=nonce,
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(log)
        db.session.commit()

        return self._build_authorize_uri(
            channel=channel, 
            state=log.generate_oauth_state(**kwargs),
            redirect_uri=urlparse.quote_plus(self.redirect_uri))

    def handle_authorize_error(self, state, error, desc):
        log, args = self._verify_and_parse_state(state)
        log.status = AuthLogs.STATUS_FAILED
        db.session.commit()
        fail_callback = log.callback_if_failed or log.callback_uri

        return add_params_to_uri(fail_callback, {
            'error': error,
            'error_description': desc,
            'provider': self.provider
        })

    def handle_authorize_success(self, code, state):
        log, args = self._verify_and_parse_state(state)
        fail_callback = log.callback_if_failed or log.callback_uri

        channel = Channels.query.filter_by(app_id=log.app_id,
                                           provider=self.provider).one_or_none()
        if not channel:
            raise RedirectLoginError(
                provider=self.provider,
                redirect_uri=fail_callback,
                error='server_internal_error',
                msg='Something wrong, cannot get application info')

        token_dict = self._get_token(channel, code, fail_callback)
        pk, attrs = self._get_profile(
            token_type=token_dict['token_type'], 
            access_token=token_dict['access_token'],
            fail_callback=fail_callback)
        try:
            profile, exists = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                pk=pk, attrs=attrs)
            log.set_authorized(social_id=profile._id, is_login=exists,
                               nonce=gen_random_token(nbytes=32))
            token = Tokens(
                provider=self.provider,
                access_token=token_dict['access_token'],
                token_type=token_dict['token_type'],
                expires_at=datetime.now() + timedelta(seconds=token_dict['expires_in']),
                refresh_token=token_dict['refresh_token'],
                jwt_token=token_dict.get('id_token'),
                social_id=profile._id
            )
            db.session.add(token)
            db.session.commit()
            return profile, log, args
        except Exception as e:
            logger.error(repr(e))
            db.session.rollback()
            raise

    def _build_authorize_uri(self, channel, redirect_uri, state):
        authorize_uri = __END_POINTS__[self.provider]['authorize_uri']
        url = authorize_uri.format(
            client_id=channel.client_id,
            redirect_uri=redirect_uri,
            scope=urlparse.quote(channel.permissions.replace(',', ' ')),
            state=state)
        return url

    def _get_token(self, channel, code, fail_callback):
        token_uri = __END_POINTS__[self.provider]['token_uri']
        res = requests.post(token_uri, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': channel.client_id,
            'client_secret': channel.client_secret
        })
        if res.status_code != 200:
            self._raise_redirect_error(
                error=res.json(), 
                msg='Getting %s access token failed: ' % self.provider.upper(),
                fail_callback=fail_callback)
        return res.json()

    def _get_profile(self, token_type, access_token, fail_callback):
        auth_header = token_type + ' ' + access_token
        profile_uri = __END_POINTS__[self.provider]['profile_uri']
        res = requests.get(profile_uri, headers={'Authorization': auth_header})
        if res.status_code != 200:
            self._raise_redirect_error(
                error=res.json(), 
                msg='Getting %s profile failed: ' % self.provider.upper(),
                fail_callback=fail_callback)
        return res.json()

    def _raise_redirect_error(self, error, msg, fail_callback):
        raise RedirectLoginError(
            error=error['error'],
            msg=msg + error['error_description'],
            redirect_uri=fail_callback,
            provider=self.provider)

    @staticmethod
    def _verify_and_parse_state(state):
        tup = AuthLogs.parse_from_oauth_state(oauth_state=state)
        if not tup:
            abort(403, 'Invalid OAuth state')
        return tup

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
    def _get_profile(self, token_type, access_token, fail_callback):
        attrs = super()._get_profile(token_type, access_token, fail_callback)
        pk = attrs['userId']
        return pk, attrs


class AmazonAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for AMAZON accounts
    """
    def _get_profile(self, token_type, access_token, fail_callback):
        attrs = super()._get_profile(token_type, access_token, fail_callback)
        pk = attrs['user_id']
        return pk, attrs


class YahooJpAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for YAHOOJP accounts
    """
    def _get_profile(self, token_type, access_token, fail_callback):
        attrs = super()._get_profile(token_type, access_token, fail_callback)
        pk = attrs['sub']
        return pk, attrs
