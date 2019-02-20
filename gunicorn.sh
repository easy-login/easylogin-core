source $(dirname $0)/.env

[[ -z "${GUNICORN_CMD_ARGS}" ]] && GUNICORN_CMD_ARGS="-k gevent -w 4 -b 0.0.0.0:5000"

gunicorn wsgi:app
