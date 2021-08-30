from flask import jsonify, redirect
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
import traceback
import sys

from sociallogin import app, logger
from sociallogin.utils import add_params_to_uri


ERROR_CODES = {
    400: 'bad_request',
    401: 'unauthorized',
    403: 'forbidden',
    404: 'not_found',
    405: 'method_not_allowed',
    409: 'conflict',
    500: 'internal_error',
    503: 'service_unavailable'
}


class SocialLoginError(Exception):
    def __init__(self, *args, **kwargs):
        self.error = kwargs.get('error')
        self.error_description = args[0] if args else kwargs.get('msg')
        self.data = kwargs.get('data')

    def __repr__(self):
        return self.error + ': ' + self.error_description

    def as_dict(self):
        return {
            'error': self.error,
            'error_description': self.error_description,
            'data': self.data
        }

    @property
    def message(self):
        """
        Alias to error_description
        """
        return self.error_description


class RedirectLoginError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        self.provider = kwargs['provider']
        self.redirect_uri = kwargs['redirect_uri']
        self.nonce = kwargs.get('nonce')
        super().__init__(*args, **kwargs)

    def as_dict(self):
        return {
            'provider': self.provider,
            'error': self.error,
            'error_description': self.error_description,
            'nonce': self.nonce
        }


class PermissionDeniedError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class BadRequestError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class UnauthorizedError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class NotFoundError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class ConflictError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class UnsupportedProviderError(NotFoundError):
    def __init__(self, **kwargs):
        super().__init__(msg='Unsupported provider', **kwargs)


class TokenParseError(BadRequestError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@app.errorhandler(RedirectLoginError)
def redirect_login_error(error):
    redirect_uri = add_params_to_uri(error.redirect_uri, **error.as_dict())
    return redirect(redirect_uri)


@app.errorhandler(LookupError)
@app.errorhandler(ValueError)
@app.errorhandler(TypeError)
def common_error(error):
    if app.config['DEBUG']:
        raise error
    else:
        msg = '{}: {}'.format(type(error).__name__, repr(error))
        return get_error_response(code=400, error=SocialLoginError(msg))


@app.errorhandler(400)
@app.errorhandler(BadRequestError)
def bad_request(error):
    return get_error_response(400, error=error)


@app.errorhandler(401)
@app.errorhandler(UnauthorizedError)
def unauthorized(error):
    return get_error_response(401, error=error)


@app.errorhandler(403)
@app.errorhandler(PermissionDeniedError)
def forbidden(error):
    return get_error_response(403, error=error)


@app.errorhandler(404)
@app.errorhandler(NotFoundError)
def not_found(error):
    return get_error_response(404, error=error)


@app.errorhandler(405)
def method_not_allowed(error):
    return get_error_response(405, error=error)


@app.errorhandler(409)
@app.errorhandler(ConflictError)
def conflict(error):
    return get_error_response(409, error=error)


@app.errorhandler(500)
@app.errorhandler(SQLAlchemyError)
@app.errorhandler(DBAPIError)
def server_internal_error(error):
    if app.config['DEBUG']:
        raise error
    else:
        # Hide error detail in production mode
        logger.error('{}: {}'.format(type(error).__name__, repr(error)))
        traceback.print_exc(file=sys.stderr)
        return get_error_response(500, error=error)


def get_error_response(code, error):
    payload = error.as_dict() \
        if isinstance(error, SocialLoginError) \
        else {'error_description': error.error_description}
    if not payload.get('error'):
        payload['error'] = ERROR_CODES.get(code, 'unknown')
    return jsonify(payload), code
