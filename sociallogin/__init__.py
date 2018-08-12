from flask import Flask
from flask_sqlalchemy import SQLAlchemy


# Define the WSGI application object
app = Flask(__name__)

# Configurations
app.config.from_object('config')

# Define the database object which is imported
# by modules and controllers
db = SQLAlchemy(app)

# Sample HTTP error handling
@app.errorhandler(404)
def not_found(error):
    pass

# Build the database:
# This will create the database file using SQLAlchemy
from sociallogin import models
db.create_all()
db.session.commit()

# Import all API endpoint definitions
from sociallogin import routes, auth