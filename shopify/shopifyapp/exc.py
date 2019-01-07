from flask import jsonify
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
import traceback
import sys

from shopifyapp import app, logger


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
        self.description = args[0] if args else kwargs.get('msg')
        self.data = kwargs.get('data')

    def __repr__(self):
        return self.error + ': ' + self.description

    def as_dict(self):
        return {
            'error': self.error,
            'error_description': self.description,
            'data': self.data
        }


class PermissionDeniedError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class BadRequestError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class NotFoundError(SocialLoginError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


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
        return get_error_response(500)


def get_error_response(code, error):
    payload = error.as_dict() if isinstance(error, SocialLoginError) \
        else {'error_description': error.description}
    if not payload.get('error'):
        payload['error'] = ERROR_CODES.get(code, 'unknown')
    return jsonify(payload), code
