export DEBUG=False
export LOG_LEVEL=INFO

gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
