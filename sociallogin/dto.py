from typing import Any, Optional, Dict

import flask

from sociallogin.mixins import \
    BaseParamMixin, \
    CallbackUriMixin, \
    ApplicationIdMixin, \
    NonceMixin, \
    PlatformMixin, \
    AssociateTokenMixin, \
    AmazonPayMixin, \
    SocialProviderMixin, \
    IntentMixin, \
    SandboxMixin, \
    MobileAuthorizeMixin, \
    OAuth2Mixin, \
    OAuth1Mixin, \
    StateMixin, \
    AssociateExtraMixin


class BaseParams(BaseParamMixin):
    def __init__(self, data: Optional[Dict[str, Any]] = None,
                 request: flask.Request = None,
                 json_body=False, **kwargs):

        data = {**(data if data else {}), **kwargs}
        if request:
            if request.method == 'GET':
                data = {**data, **request.args}
            elif request.method in ['POST', 'PUT']:
                if json_body:
                    data = {**data, **request.json}
                else:
                    data = {**data, **request.form}
        self._data = data

    def to_dict(self):
        return self._data


class OAuthAuthorizeParams(
    BaseParams,
    ApplicationIdMixin,
    SocialProviderMixin,
    IntentMixin,
    CallbackUriMixin,
    NonceMixin,
    PlatformMixin,
    AssociateTokenMixin,
    AmazonPayMixin,
    SandboxMixin,
    MobileAuthorizeMixin
):
    def __init__(self, data=None, **kwargs):
        super().__init__(data, **kwargs)


class OAuthCallbackParams(
    BaseParams,
    SocialProviderMixin,
    StateMixin,
    OAuth2Mixin,
    OAuth1Mixin
):
    def __init__(self, data=None, **kwargs):
        super().__init__(data, **kwargs)


class OAuthSessionParams(
    BaseParams,
    SocialProviderMixin,
    SandboxMixin,
    PlatformMixin,
    NonceMixin,
    MobileAuthorizeMixin,
    AssociateExtraMixin,
    AmazonPayMixin
):
    def __init__(self, data=None, **kwargs):
        super().__init__(data, **kwargs)


class OAuth2TokenPack(BaseParams, OAuth2Mixin):
    def __init__(self, data=None, **kwargs):
        super().__init__(data, **kwargs)


class OAuth1TokenPack(BaseParams, OAuth1Mixin):
    def __init__(self, data=None, **kwargs):
        super().__init__(data, **kwargs)
