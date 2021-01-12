from sociallogin.exc import UnsupportedProviderError

from .base import OAuthBackend
from .line import LineBackend
from .amazon import AmazonBackend, AmazonSandboxBackend
from .yahoojp import YahooJpBackend
from .facebook import FacebookBackend
from .google import GoogleBackend
from .twitter import TwitterBackend


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


_valid_provider_names = {
    'line', 'amazon', 'facebook', 'yahoojp', 'facebook', 'google',
    'stripe', 'paypal', 'spotify', 'shopify', 'instagram', 'apple'
}


def is_valid_provider(provider):
    return provider in _valid_provider_names
