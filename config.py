from dotenv import load_dotenv
load_dotenv()

import os

# Statement for enabling the development environment
DEBUG = bool(os.getenv('DEBUG', 'True'))

# Define the application directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

TIME_ZONE = os.getenv('TIME_ZONE', 'Asia/Ho_Chi_Minh')

# SERVER_NAME = 'http://localhost:5000'
if DEBUG:
    SECRET_KEY = os.getenv('SECRET_KEY', 'soci@ll0gin.c48COByeIVl0NKUxsfgYYw')
else:
    # You must provide SECRET_KEY in prodution
    SECRET_KEY = os.getenv('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError('SECRET_KEY must not be None')

# Define the database
if DEBUG:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'SQLALCHEMY_DATABASE_URI',
        'mysql+pymysql://root:root@localhost/easylogin?charset=utf8mb4'
    )
else:
    # You must provide SQLALCHEMY_DATABASE_URI in prodution
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_NATIVE_UNICODE = True

DATABASE_CONNECT_OPTIONS = {}
JSON_SORT_KEYS = True

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = os.getenv(
    'LOG_FORMAT',
    '[%(asctime)s] %(levelname)s %(filename)s:%(lineno)d - %(message)s'
)
LOG_DATE_FORMAT = os.getenv('LOG_DATE_FORMAT', '%Y-%m-%d %H:%M:%S')
LOG_DIR = os.getenv('LOG_DIR', '/var/log/sociallogin')
LOG_STYLE = os.getenv('LOG_STYLE', 'inline')
