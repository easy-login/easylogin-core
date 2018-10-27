from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

import logging
import os


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
from sociallogin.utils import EasyLogger
logger = EasyLogger(impl=app.logger)
logger.load_from_config(app.config)

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models
db.create_all()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import auth, routes, exc
auth.init_app(app)


def init_logging(app_):
    log_dir = app_.config['LOG_DIR']
    os.makedirs(name=log_dir, mode=0o755, exist_ok=True)
    file_handler = logging.FileHandler(filename=log_dir + '/server.log')
    file_handler.setFormatter(logging.Formatter(
        fmt=app_.config['LOG_FORMAT'],
        datefmt=app_.config['LOG_DATE_FORMAT']
    ))
    app_.logger.setLevel(app.config['LOG_LEVEL'])
    app_.logger.addHandler(file_handler)


init_logging(app)
