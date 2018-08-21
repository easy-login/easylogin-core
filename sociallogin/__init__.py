from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


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

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models
db.create_all()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import routes, auth, exc
auth.init_app(app)

# Only for the first time in development mode
# db.session.bulk_save_objects([
#     models.Channels(
#         provider='line',
#         client_id='1600288055',
#         client_secret='9dbe2e69e669ec9f750a9a9b034ce481',
#         permissions='profile,openid,email',
#         app_id=3
#     ),
#     models.Channels(
#         provider='amazon',
#         client_id='amzn1.application-oa2-client.e4f978fd4ef347ddbf8206d16f0df5eb',
#         client_secret='ad90102af6bb3de8bd0338bba92000ff427f7a47467460b49aa0a0c0ef2a8592',
#         permissions='profile,postal_code',
#         app_id=3
#     )
# ])
# db.session.commit()