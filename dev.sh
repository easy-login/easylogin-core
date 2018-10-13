#!/bin/bash

export FLASK_APP=sociallogin:app
export FLASK_DEBUG=1

flask run -h 0.0.0.0 -p "${1:-5000}" --cert $2 --key $3