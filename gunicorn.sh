. $(dirname $0)/.env.sh

gunicorn wsgi:app
