from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

import logging
import os
import json


class EasyLogger(object):
    STYLE_SIMPLE = 'simple'
    STYLE_INLINE = 'inline'
    STYLE_JSON = 'json'
    STYLE_HYBRID = 'hybrid'

    def __init__(self, impl, style=STYLE_INLINE):
        self.impl = impl
        self.style = style

    def load_from_config(self, config):
        self.style = config['LOG_STYLE']

    def debug(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.DEBUG, msg, style, *args, **kwargs)

    def info(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.INFO, msg, style, *args, **kwargs)

    def warning(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.WARNING, msg, style, *args, **kwargs)

    def warn(self, msg, *args, style=None, **kwargs):
        self.warning(msg, *args, style=style, **kwargs)

    def error(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, *args, **kwargs)

    def critical(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.CRITICAL, msg, style, *args, **kwargs)

    def exception(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, exc_info=1, *args, **kwargs)

    def _print_log(self, lvl, msg, style, *args, exc_info=0, **kwargs):
        if self.impl.level > lvl:
            return
        style = style or self.style
        if style == self.STYLE_INLINE:
            arg_str = ' '.join(args)
            kwarg_str = ' '.join(['%s=%s' % (k, self._check_quote(v))
                                  for k, v in kwargs.items()])
            msg += ' \t' + arg_str + '\t' + kwarg_str
        elif style == self.STYLE_JSON:
            msg = '\n' + json.dumps({
                'msg': msg,
                'args': args,
                'kwargs': kwargs
            }, ensure_ascii=False, indent=2)
        elif style == self.STYLE_HYBRID:
            msg += ' \t' + ' '.join(args)
            if kwargs:
                msg += '\n' + json.dumps(kwargs, indent=2, ensure_ascii=False)
        else:
            if args:
                msg += '\t' + str(args or '')
            if kwargs:
                msg += '\t' + str(kwargs or '')
        self.impl.log(lvl, '%s - %s' % (get_remote_ip(request), msg), exc_info=exc_info)

    @staticmethod
    def _check_quote(s):
        s = str(s)
        return '"%s"' % s if ' ' in s else s


def init_logging(app_):
    log_dir = app_.config['LOG_DIR']
    os.makedirs(log_dir, mode=0o755, exist_ok=True)
    file_handler = logging.FileHandler(filename=log_dir + '/server.log')
    file_handler.setFormatter(logging.Formatter(
        fmt=app_.config['LOG_FORMAT'],
        datefmt=app_.config['LOG_DATE_FORMAT']
    ))
    app_.logger.setLevel(app.config['LOG_LEVEL'])
    app_.logger.addHandler(file_handler)

    # import sentry_sdk
    # from sentry_sdk.integrations.flask import FlaskIntegration
    #
    # sentry_sdk.init(
    #     dsn="https://889175480fbc46daa8de150c01886aa9@sentry.io/1317697",
    #     integrations=[FlaskIntegration()]
    # )


def get_remote_ip(req):
    if req.environ.get('HTTP_X_FORWARDED_FOR'):
        return req.environ['HTTP_X_FORWARDED_FOR']
    elif req.environ.get('HTTP_X_REAL_IP'):
        return req.environ['HTTP_X_REAL_IP']
    else:
        return req.remote_addr


# Define the WSGI application object
app = Flask(__name__)

# Configurations
app.config.from_object('config')

# Define the database object which is imported
# by modules and controllers
db = SQLAlchemy(app)

# Define Login Manager object
login_manager = LoginManager()
login_manager.init_app(app)

# Define logger object
logger = EasyLogger(impl=app.logger)
logger.load_from_config(app.config)
init_logging(app)

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models

db.create_all()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import auth, routes, hosted, exc

auth.init_app(app)
