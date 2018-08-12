# Statement for enabling the development environment
DEBUG = True

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))  

# SERVER_NAME = 'http://localhost:5000'

# Define the database
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:root@localhost/sociallogin?charset=utf8mb4'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_NATIVE_UNICODE = True

DATABASE_CONNECT_OPTIONS = {}

LOG_LEVEL = 'INFO'
LOG_FORMAT = ''
LOG_DIR = '/tmp/sociallogin/logs'