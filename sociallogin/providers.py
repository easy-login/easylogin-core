import urllib.parse as urlparse
import hashlib
from flask import request

from sociallogin import db
from sociallogin.models import Sites, SiteProviders, Logs
from sociallogin.utils import get_or_abort, b64encode_string


_provider_endpoints = {
    'line': {
        'authorize_uri': '''
            https://access.line.me/oauth2/v2.1/authorize?response_type=code
            &client_id={client_id}
            &state={state}
            &scope={scope}
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.line.me/oauth2/v2.1/token/'
    },
    'amazon': {
        'authorize_uri': '''
            https://www.amazon.com/ap/oa?response_type=code
            &client_id={client_id}
            &state={state}
            &scope=profile
            &redirect_uri={redirect_uri}'''.strip().replace('\n', '').replace(' ', ''),
        'token_uri': 'https://api.amazon.com/auth/o2/token'
    }
}


def get_auth_handler(provider):
    if provider == 'line':
        return LineAuthHandler()
    else: 
        return None


class ProviderAuthHandler(object):
    
    def build_authorize_uri(self, provider, site_id, redirect_uri):
        site = Sites.query.filter_by(_id=site_id).first_or_404()
        site_provider = SiteProviders.query.filter_by(
            site_id=site_id, 
            provider=provider).first_or_404()

        log = Logs(
            provider=provider,
            ua=request.headers['User-Agent'],
            ip=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        s = 'cu={}&sid={}'.format(site.callback_uri, log._id)
        data = b64encode_string(s, urlsafe=True)

        return self._build_authorize_uri(
            client_id=site_provider.client_id, 
            redirect_uri=redirect_uri + '&ed=' + data,
            permissions=site_provider.permissions,
            state=hashlib.sha1(data.encode('utf8')).hexdigest()
        )

    def handle_authorize_response(self):
        pass

    def _build_authorize_uri(self, client_id, redirect_uri, permissions, state):
        # Logs.update.where(_id=log_id).values(status='success')
        pass


class LineAuthHandler(ProviderAuthHandler):

    def _build_authorize_uri(self, client_id, redirect_uri, permissions, state):
        endpoints = _provider_endpoints.get('line')
        url = endpoints['authorize_uri'].format(
            client_id=client_id,
            redirect_uri=urlparse.quote_plus(redirect_uri),
            scope=urlparse.quote(permissions.replace(',', ' ')),
            state=state)
        return url

    def _handle_authorize_response(args):
        pass
