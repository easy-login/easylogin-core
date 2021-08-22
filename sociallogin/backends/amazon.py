import json
import urllib.parse as up

from flask import make_response, redirect

from sociallogin import logger
from sociallogin.backends import OAuthBackend
from sociallogin.entities import OAuthSessionParams
from sociallogin.models import AuthLogs, Tokens
from sociallogin.utils import add_params_to_uri, unix_time_millis


class AmazonBackend(OAuthBackend):
    """
    Authentication handler for AMAZON accounts
    """
    AUTHORIZE_URI = 'https://apac.account.amazon.com/ap/oa?response_type=code'
    TOKEN_URI = 'https://api.amazon.com/auth/o2/token'
    VERIFY_TOKEN_URI = 'https://api.amazon.com/auth/o2/tokeninfo'
    PROFILE_URI = 'https://api.amazon.com/user/profile'
    IDENTIFY_ATTRS = ['user_id']

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

    def _make_web_authorize_success_response(self, token: Tokens):
        parent_resp = super()._make_web_authorize_success_response(token)

        amz_pay_enabled = self.channel.option_enabled('amazon_pay')
        if not amz_pay_enabled or self.log.intent != AuthLogs.INTENT_PAY_WITH_AMAZON:
            return parent_resp

        resp = make_response(parent_resp)
        cookie_object = {
            "access_token": token.access_token,
            "max_age": 3300,
            "expiration_date": unix_time_millis(token.expires_at),
            "client_id": self.channel.client_id,
            "scope": self._perms_for_pay()
        }
        domain = self.session.lpwa_domain or self.extract_domain_for_cookie(url=self.log.callback_uri)
        resp.set_cookie(key='amazon_Login_state_cache',
                        value=up.quote(json.dumps(cookie_object), safe=''),
                        domain=domain, expires=None, max_age=None)
        resp.set_cookie(key='amazon_Login_accessToken',
                        value=token.access_token,
                        domain=domain, expires=None, max_age=3300)
        logger.debug('Set cookie for amazon pay', domain=domain or 'localhost')
        return resp

    def _perms_for_pay(self):
        return self.channel.get_perms_as_oauth_scope() \
               + ' payments:widget payments:shipping_address'

    @staticmethod
    def extract_domain_for_cookie(url, subdomain=True):
        netloc = str(up.urlparse(url).netloc)
        if netloc.startswith('localhost'):
            return None
        else:
            parts = netloc.split('.')
            domain = parts[-2] + '.' + parts[-1]
            if subdomain:
                domain = '.' + domain
            return domain


class AmazonSandboxBackend(AmazonBackend):
    """
    Authentication handler for AMAZON sandbox accounts (for example use with Amazon Pay...)
    """
    AUTHORIZE_URI = 'https://apac.account.amazon.com/ap/oa?response_type=code&sandbox=true'
    TOKEN_URI = 'https://api.sandbox.amazon.com/auth/o2/token'
    VERIFY_TOKEN_URI = 'https://api.amazon.com/auth/o2/tokeninfo'
    PROFILE_URI = 'https://api.amazon.com/auth/o2/tokeninfo'
