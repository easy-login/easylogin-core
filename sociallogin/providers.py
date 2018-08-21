import urllib.parse as urlparse
import requests
from datetime import datetime, timedelta
from flask import request, abort, jsonify, url_for

from sociallogin import db
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, SocialProfiles
from sociallogin.utils import b64encode_string, b64decode_string, is_same_uri,
                            gen_random_token, convert_CameCase_to_snake_case


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


def get_auth_handler(provider):
    if provider == 'line':
        return LineAuthHandler(provider)
    elif provider == 'amazon':
        return AmazonAuthHandler(provider)
    elif provider == 'yahoojp':
        return YahooJpAuthHandler(provider)
    else: 
        return abort(404, 'Unsupported provider')


class ProviderAuthHandler(object):

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)
    
    def build_authorize_uri(self, app_id, callback_uri, callback_if_failed=None):
        app = Apps.query.filter_by(_id=app_id).first_or_404()
        channel = Channels.query.filter_by(
            app_id=app_id, 
            provider=self.provider).first_or_404()

        # if not is_same_uri(app.callback_uri, callback_uri):
        #     abort(403, 'Callback URI must same as what was configured in admin settings')

        nonce = gen_random_token(nbytes=16)
        log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            ua=request.headers['User-Agent'],
            ip=request.remote_addr,
            nonce=nonce,
            callback_uri=callback_uri
        )
        db.session.add(log)
        db.session.commit()

        return self._build_authorize_uri(
            channel=channel, 
            redirect_uri=urlparse.quote_plus(self.redirect_uri),
            state=b64encode_string(nonce + '.' + str(log._id), urlsafe=True)
        )

    def handle_authorize_error(self, provider, log_id, args):
        AuthLogs.update.where(_id=log_id).values(status='failed')
        db.session.commit()

    def handle_authorize_response(self, code, state):
        log = self._verify_state(state)
        channel = Channels.query.filter_by(
            app_id=log.app_id, 
            provider=self.provider).first_or_404()

        token_dict = self._get_token(channel, code, state)
        pk, attrs = self._get_profile(token_dict['token_type'], token_dict['access_token'])
        try:
            profile = SocialProfiles.add_or_update(
                app_id=log.app_id,
                provider=self.provider,
                pk=pk, attrs=attrs)

            log.once_token = gen_random_token(nbytes=32)
            log.token_expires = datetime.now() + timedelta(seconds=600)
            log.social_id = profile._id
            log.status = AuthLogs.STATUS_AUTHORIZED

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
            return profile._id, log.once_token, log.callback_uri
        except:
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

    def _get_token(self, channel, code, state):
        token_uri = __END_POINTS__[self.provider]['token_uri']
        res = requests.post(token_uri, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': channel.client_id,
            'client_secret': channel.client_secret
        })
        if res.status_code != 200:
            abort(res.status_code, {
                'msg': 'Error when getting %s access token' % self.provider.upper(),
                'error': res.json()
            })
        return res.json()

    def _get_profile(self, token_type, access_token):
        auth_header = token_type + ' ' + access_token
        profile_uri = __END_POINTS__[self.provider]['profile_uri']
        res = requests.get(profile_uri, headers={'Authorization': auth_header})
        if res.status_code != 200:
            abort(res.status_code, {
                'msg': 'Error when getting %s profile' % self.provider.upper(),
                'error': res.json()
            })
        return res.json()

    def _verify_state(self, state):
        try:
            params = b64decode_string(state, urlsafe=True).split('.')
            nonce = params[0]
            log_id = int(params[1])

            log = AuthLogs.query.filter_by(_id=log_id).first_or_404()
            if log.nonce != nonce:
                abort(403, 'Invalid state')
            return log
        except KeyError:
            abort(400, 'Bad format parameter state')


class LineAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for LINE accounts
    """
    def _get_profile(self, token_type, access_token):
        attrs = super()._get_profile(token_type, access_token)
        pk = attrs['userId']
        return pk, attrs


class AmazonAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for AMAZON accounts
    """
    def _get_profile(self, token_type, access_token):
        attrs = super()._get_profile(token_type, access_token)
        pk = attrs['user_id']
        return pk, attrs


class YahooJpAuthHandler(ProviderAuthHandler):
    """
    Authentication handler for YAHOOJP accounts
    """
    def _get_profile(self, token_type, access_token):
        attrs = super()._get_profile(token_type, access_token)
        pk = attrs['sub']
        return pk, attrs
