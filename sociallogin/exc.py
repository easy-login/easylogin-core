import urllib.parse as urlparse
from flask import jsonify, redirect
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from sociallogin import app
from sociallogin.utils import add_params_to_uri


class BadRequestError(ValueError):
    pass


class PermissionDeniedError(ValueError):
    pass


class NotFoundError(ValueError):
    pass


class ServerInternalError(ValueError):
    pass


class SocialLoginError(Exception):
    def __init__(self, error, desc=None):
        self.error = error
        self.error_description = desc

    def as_dict(self):
        return {
            'error': urlparse.quote(self.error),
            'error_description': urlparse.quote(self.error_description)
        }


class RedirectLoginError(SocialLoginError):
    def __init__(self, redirect_uri, error, desc=None):
        super().__init__(error, desc)
        self.redirect_uri = redirect_uri


@app.errorhandler(RedirectLoginError)
def redirect_login_error(error):
    redirect_uri = add_params_to_uri(error.redirect_uri, error.as_dict())
    return redirect(redirect_uri)


@app.errorhandler(400)
@app.errorhandler(BadRequestError)
@app.errorhandler(KeyError)
@app.errorhandler(ValueError)
def bad_request(error):
    msg = error.message if isinstance(error, BadRequestError) else error.description
    return get_error_payloads(400, error_description=msg)


@app.errorhandler(401)
def unauthorized(error):
    return get_error_payloads(401, error_description=error.description)


@app.errorhandler(403)
@app.errorhandler(PermissionDeniedError)
def forbidden(error):
    msg = error.message if isinstance(error, PermissionDeniedError) else error.description
    return get_error_payloads(403, error_description=msg)


@app.errorhandler(404)
@app.errorhandler(NotFoundError)
def not_found(error):
    msg = error.message if isinstance(error, NotFoundError) else error.description
    return get_error_payloads(404, error_description=msg)


@app.errorhandler(405)
def method_not_allowed(error):
    return get_error_payloads(405, error_description=error.description)


@app.errorhandler(409)
def conflict(error):
    return get_error_payloads(409, error_description=error.description)


@app.errorhandler(500)
@app.errorhandler(ServerInternalError)
def server_internal_error(error):
    msg = error.message if isinstance(error, ServerInternalError) else error.description
    return get_error_payloads(500, error_description=msg)


@app.errorhandler(SQLAlchemyError)
@app.errorhandler(DBAPIError)
def sql_error(error):
    if app.config['DEBUG']:
        app.logger.error(error)
        return get_error_payloads(500, error_description=error.message)
    # Hide error detail in production mode
    else:
        return get_error_payloads(503)


def get_error_payloads(code, error=None, error_description=''):
    if not error:
        if code == 400:
            error = 'Bad request'
        elif code == 401:
            error = 'Unauthorized'
        elif code == 403:
            error = 'Forbidden'
        elif code == 404:
            error = 'Not found'
        elif code == 405:
            error = 'Method Not Allowed'
        elif code == 409:
            error = 'Conflict'
        elif code == 500:
            error = 'Internal server error'
        elif code == 503:
            error = 'Service Unavailable'
    return jsonify({
        'error': error,
        'error_description': error_description
    }), code
