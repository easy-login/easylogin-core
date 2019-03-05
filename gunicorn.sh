. $(dirname $0)/.env

gunicorn -b 0.0.0.0:80 wsgi:app
