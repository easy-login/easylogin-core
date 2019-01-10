export DEBUG=False
export LOG_LEVEL=INFO

gunicorn -w 1 -b 0.0.0.0:8888 wsgi:app
