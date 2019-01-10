from flask import Flask
from flask_sqlalchemy import SQLAlchemy

import os
import json
import logging


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


# Define the WSGI application object
app = Flask(__name__, template_folder='templates')

# Configurations
app.config.from_object('config')

# Define the database object which is imported
# by modules and controllers
db = SQLAlchemy(app)

# Define logger object
from shopifyapp.utils import EasyLogger
logger = EasyLogger(impl=app.logger)
logger.load_from_config(app.config)
init_logging(app)

# Build the database:
# This will create the database file using SQLAlchemy
from shopifyapp import models

db.create_all()
db.session.commit()

from shopifyapp import exc, routes
