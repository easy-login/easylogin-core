from flask import jsonify, redirect
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from sociallogin import app
from sociallogin.utils import add_params_to_uri


class SocialLoginError(Exception):
    def __init__(self, error, msg=None):
        self.error = error
        self.message = msg


class RedirectLoginError(SocialLoginError):
    def __init__(self, provider, redirect_uri, error, msg=None):
        super().__init__(error, msg)
        self.provider = provider
        self.redirect_uri = redirect_uri

    def as_dict(self):
        return {
            'provider': self.provider,
            'error': self.error,
            'error_description': self.message
        }


@app.errorhandler(RedirectLoginError)
def redirect_login_error(error):
    redirect_uri = add_params_to_uri(error.redirect_uri, error.as_dict())
    return redirect(redirect_uri)


@app.errorhandler(KeyError)
@app.errorhandler(ValueError)
@app.errorhandler(TypeError)
def common_error(error):
    msg = '{}: {}'.format(type(error).__name__, str(error))
    return get_error_payloads(400, error_description=msg)


@app.errorhandler(SQLAlchemyError)
@app.errorhandler(DBAPIError)
def sql_error(error):
    if app.config['DEBUG']:
        msg = '{}: {}'.format(type(error).__name__, str(error))
        return get_error_payloads(500, error_description=msg)
    # Hide error detail in production mode
    else:
        return get_error_payloads(503)


@app.errorhandler(400)
def bad_request(error):
    return get_error_payloads(400, error_description=error.description)


@app.errorhandler(401)
def unauthorized(error):
    return get_error_payloads(401, error_description=error.description)


@app.errorhandler(403)
def forbidden(error):
    return get_error_payloads(403, error_description=error.description)


@app.errorhandler(404)
def not_found(error):
    return get_error_payloads(404, error_description=error.description)


@app.errorhandler(405)
def method_not_allowed(error):
    return get_error_payloads(405, error_description=error.description)


@app.errorhandler(409)
def conflict(error):
    return get_error_payloads(409, error_description=error.description)


@app.errorhandler(500)
def server_internal_error(error):
    return get_error_payloads(500, error_description=error.description)


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
