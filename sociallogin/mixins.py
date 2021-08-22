from typing import Dict

from werkzeug.utils import cached_property

from sociallogin.utils import smart_str2bool, smart_str2int


class BaseParamMixin:
    _data: Dict


class ApplicationIdMixin(BaseParamMixin):
    @cached_property
    def app_id(self) -> str:
        return self._data['app_id']


class SocialProviderMixin(BaseParamMixin):
    @cached_property
    def provider(self) -> str:
        return self._data.get('provider', '')


class IntentMixin(BaseParamMixin):
    @cached_property
    def intent(self) -> str:
        return self._data.get('intent', '')


class CallbackUriMixin(BaseParamMixin):
    @cached_property
    def success_callback(self) -> str:
        return self._data['callback_uri']

    @cached_property
    def failed_callback(self) -> str:
        return self._data.get('callback_if_failed', '')


class NonceMixin(BaseParamMixin):
    @cached_property
    def nonce(self) -> str:
        return self._data.get('nonce', '')


class PlatformMixin(BaseParamMixin):
    @cached_property
    def platform(self) -> str:
        return self._data.get('platform', '')    


class AssociateTokenMixin(BaseParamMixin):
    @cached_property
    def associate_token(self) -> str:
        return self._data.get('associate_token', '')
    
    
class AssociateExtraMixin(BaseParamMixin):
    @cached_property
    def dst_social_id(self) -> str:
        return self._data.get('dst_social_id', '')


class AmazonPayMixin(BaseParamMixin):
    @cached_property
    def site_domain(self) -> str:
        return self._data.get('site_domain', '')

    @cached_property
    def lpwa_domain(self) -> str:
        return self._data.get('lpwa_domain', '')


class SandboxMixin(BaseParamMixin):
    @cached_property
    def sandbox(self) -> bool:
        return smart_str2bool(self._data.get('sandbox', ''))


class MobileAuthorizeMixin(BaseParamMixin):
    @cached_property
    def code_challenge(self) -> str:
        return self._data.get('code_challenge', '')

    @cached_property
    def code_verifier(self) -> str:
        return self._data.get('code_verifier', '')


class StateMixin(BaseParamMixin):
    @cached_property
    def state(self) -> str:
        return self._data.get('state', '')


class OAuth2Mixin(BaseParamMixin):
    @cached_property
    def code(self) -> str:
        return self._data.get('code', '')

    @cached_property
    def access_token(self) -> str:
        return self._data.get('access_token', '')

    @cached_property
    def token_type(self) -> str:
        return self._data.get('token_type', '')

    @cached_property
    def expires_in(self) -> int:
        return smart_str2int(self._data.get('expires_in', ''))

    @cached_property
    def refresh_token(self) -> str:
        return self._data.get('refresh_token', '')

    @cached_property
    def id_token(self) -> str:
        return self._data.get('id_token', '')


class OAuth1Mixin(BaseParamMixin):
    @cached_property
    def oauth_token_secret(self) -> str:
        return self._data.get('oauth_token_secret', '')

    @cached_property
    def oauth_token(self) -> str:
        return self._data.get('oauth_token', '')

    @cached_property
    def oauth_verifier(self) -> str:
        return self._data.get('oauth_verifier', '')
