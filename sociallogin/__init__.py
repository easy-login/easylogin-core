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

# Sample HTTP error handling
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': error.description,
        'code': 404
    }), 404

@app.errorhandler(403)
def permission_denied(error):
    return jsonify({
        'error': error.description,
        'code': 403
    }), 403

@app.errorhandler(401)
def bad_request(error):
    return jsonify({
        'error': error.description,
        'code': 401
    }), 401

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': error.description,
        'code': 400
    }), 400

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models
db.create_all()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import routes, auth
auth.init_app(app)