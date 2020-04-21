from dotenv import load_dotenv
load_dotenv()

import os

# Statement for enabling the development environment
DEBUG = (os.getenv('DEBUG', 'True') != 'False')

# Define the application directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

TIME_ZONE = os.getenv('TIME_ZONE', 'Asia/Ho_Chi_Minh')

# SERVER_NAME = 'http://localhost:5000'
SECRET_KEY = os.getenv('SECRET_KEY', 'soci@ll0gin.c48COByeIVl0NKUxsfgYYw')

# Define the database
SQLALCHEMY_DATABASE_URI = os.getenv(
    'SQLALCHEMY_DATABASE_URI',
    'mysql+pymysql://root:root@localhost/easylogin?charset=utf8mb4'
)
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_NATIVE_UNICODE = True

DATABASE_CONNECT_OPTIONS = {}
JSON_SORT_KEYS = True

LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
LOG_FORMAT = os.getenv(
    'LOG_FORMAT',
    '[%(asctime)s] %(levelname)s %(filename)s:%(lineno)d - %(message)s'
)
LOG_DATE_FORMAT = os.getenv('LOG_DATE_FORMAT', '%Y-%m-%d %H:%M:%S')
LOG_DIR = os.getenv('LOG_DIR', '/var/log/sociallogin')
LOG_STYLE = os.getenv('LOG_STYLE', 'inline')
