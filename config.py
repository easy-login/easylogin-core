# Statement for enabling the development environment
DEBUG = True

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))  

# SERVER_NAME = 'http://localhost:5000'
JWT_SECRET_KEY = 'soci@llogin.dev'
JWT_ALGORITHM = 'HS512'

# Define the database
# SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:root@localhost/sociallogin?charset=utf8mb4'
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://guest:123456@192.168.9.89/nhatanhdb?charset=utf8mb4'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_NATIVE_UNICODE = True

DATABASE_CONNECT_OPTIONS = {}
JSON_SORT_KEYS = True

LOG_LEVEL = 'DEBUG' if DEBUG else 'INFO'
LOG_FORMAT = '[%(asctime)s] %(levelname)s %(filename)s:%(lineno)d - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_DIR = '/tmp/sociallogin/logs'
