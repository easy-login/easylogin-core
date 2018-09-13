from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import logging


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
logger = app.logger

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models
db.create_all()
# models.Providers.init()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import auth, routes, exc
auth.init_app(app)


def init_logging(_app):
    file_handler = logging.FileHandler(filename=_app.config['LOG_DIR'] + '/server.log')
    file_handler.setFormatter(logging.Formatter(
        fmt=_app.config['LOG_FORMAT'],
        datefmt=_app.config['LOG_DATE_FORMAT']
    ))
    _app.logger.setLevel(app.config['LOG_LEVEL'])
    _app.logger.addHandler(file_handler)


init_logging(app)
