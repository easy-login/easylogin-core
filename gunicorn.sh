. $(dirname $0)/.env

gunicorn wsgi:app
