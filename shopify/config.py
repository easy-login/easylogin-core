import os

# Statement for enabling the development environment
DEBUG = (os.getenv('DEBUG', 'True') != 'False')

# Define the application directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

TIME_ZONE = os.getenv('TIME_ZONE', 'Asia/Tokyo')

# SERVER_NAME = 'http://localhost:5000'
SECRET_KEY = os.getenv('SECRET_KEY', 'sh0p!fy.a39b29c6dead197d')

# Define the database
SQLALCHEMY_DATABASE_URI = os.getenv(
    'SQLALCHEMY_DATABASE_URI',
    'mysql+pymysql://root:root@localhost/shopify?charset=utf8mb4'
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
LOG_DIR = os.getenv('LOG_DIR', '/var/log/sociallogin/shopifyapp')
LOG_STYLE = os.getenv('LOG_STYLE', 'inline')


# Shopify settings
SHOPIFY_OAUTH_CLIENT_ID = os.getenv('SHOPIFY_OAUTH_CLIENT_ID', '983f69980c64f0ac587c17d705cbdac0')
SHOPIFY_OAUTH_CLIENT_SECRET = os.getenv('SHOPIFY_OAUTH_CLIENT_SECRET', 'e21cee33478c86475dab8690dcfcb8da')
SHOPIFY_APP_NAME = os.getenv('SHOPIFY_APP_NAME', 'easylogin-auth-demo')
