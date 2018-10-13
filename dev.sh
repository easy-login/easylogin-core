#!/bin/bash

export FLASK_APP=sociallogin:app
export FLASK_ENV=development

flask run -h 0.0.0.0 -p "${1:-5000}"