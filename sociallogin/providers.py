import urllib.parse as urlparse
import hashlib
import uuid
from flask import request, abort, jsonify, url_for
import requests
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError, DBAPIError

from sociallogin import db
from sociallogin.models import Sites, SiteProviders, Logs, Users, UserAttrs, Tokens
from sociallogin.utils import b64encode_string, b64decode_string, is_same_uri


_provider_endpoints = {
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

    },
    'amazon': {
        'authorize_uri': '''
            https://www.amazon.com/ap/oa?response_type=code
            &client_id={client_id}
            &state={state}
            &scope=profile
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token',
        'profile_uri': ''
    }
}


def get_auth_handler(provider):
    if provider == 'line':
        return LineAuthHandler(provider)
    else: 
        return abort(404, 'Unsupported provider')


class ProviderAuthHandler(object):

    def __init__(self, provider):
        self.provider = provider
        self.redirect_uri = url_for('authorize_callback', _external=True, provider=provider)
    
    def build_authorize_uri(self, site_id, callback_uri):
        site = Sites.query.filter_by(_id=site_id).first_or_404()
        site_provider = SiteProviders.query.filter_by(
            site_id=site_id, 
            provider=self.provider).first_or_404()

        if not is_same_uri(site.callback_uri, callback_uri):
            abort(403, 'Callback URI must same as ' + site.callback_uri)

        nonce = hashlib.sha1(uuid.uuid4().bytes).hexdigest()
        log = Logs(
            provider=self.provider,
            site_id=site_id,
            ua=request.headers['User-Agent'],
            ip=request.remote_addr,
            nonce=nonce,
            callback_uri=callback_uri
        )
        db.session.add(log)
        db.session.commit()

        return self._build_authorize_uri(
            site_provider=site_provider, 
            redirect_uri=urlparse.quote_plus(self.redirect_uri),
            state=b64encode_string(nonce + '.' + str(log._id), urlsafe=True)
        )

    def _build_authorize_uri(self, site_provider, redirect_uri, state):
        raise NotImplementedError()

    def handle_authorize_error(self, provider, log_id, args):
        Logs.update.where(_id=log_id).values(status='failed')
        db.session.commit()

    def handle_authorize_response(self, code, state):
        log = self._verify_state(state)
        site_provider = SiteProviders.query.filter_by(
            site_id=log.site_id, 
            provider=self.provider).first_or_404()

        identifier, token, attrs = self._get_profile_token(site_provider, code, state)
        try:
            user = Users.add_or_update(
                provider=self.provider, 
                identifier=identifier, site_id=log.site_id)
            token.user_id = user._id

            # once_token = hashlib.sha1(uuid.uuid4().bytes).hexdigest()
            # log.once_token = once_token
            # db.session.save(log)

            db.session.add(UserAttrs(_id=user._id, log_id=log._id, attrs=attrs))
            db.session.add(token)
            db.session.commit()
            return user._id, log.callback_uri
        except:
            db.session.rollback()
            raise

    def _get_profile_token(self, site_provider, code, state):
        raise NotImplementedError()

    def _verify_state(self, state):
        try:
            params = b64decode_string(state, urlsafe=True).split('.')
            nonce = params[0]
            log_id = int(params[1])

            log = Logs.query.filter_by(_id=log_id).first_or_404()
            if log.nonce != nonce:
                abort(403, 'Invalid state')
            return log
        except KeyError:
            abort(400, 'Bad format parameter state')


class LineAuthHandler(ProviderAuthHandler):

    def _build_authorize_uri(self, site_provider, redirect_uri, state):
        authorize_uri = _provider_endpoints['line']['authorize_uri']
        url = authorize_uri.format(
            client_id=site_provider.client_id,
            redirect_uri=redirect_uri,
            scope=urlparse.quote(site_provider.permissions.replace(',', ' ')),
            state=state)
        return url

    def _get_profile_token(self, site_provider, code, state):
        token_uri = _provider_endpoints['line']['token_uri']
        res = requests.post(token_uri, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': site_provider.client_id,
            'client_secret': site_provider.client_secret
        })
        if res.status_code != 200:
            print('get token error', res.json())
            abort(res.status_code, {
                'msg': 'Error when getting LINE access token',
                'error': res.json()
            })

        token_dict = res.json()
        token = Tokens(
            provider='line',
            access_token=token_dict['access_token'],
            expires_at=datetime.now() + timedelta(seconds=token_dict['expires_in']),
            refresh_token=token_dict['refresh_token'],
            jwt_token=token_dict.get('id_token'),
            scope=token_dict['scope'],
            token_type=token_dict['token_type']
        )

        profile_uri = _provider_endpoints['line']['profile_uri']
        res = requests.get(profile_uri, headers={'Authorization': 'Bearer ' + token.access_token})
        if res.status_code != 200:
            abort(res.status_code, {
                'msg': 'Error when getting LINE profile',
                'error': res.json()
            })

        attrs = res.json()
        identifier = attrs['userId']
        return identifier, token, attrs


