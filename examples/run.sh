#!/bin/bash

export FLASS_APP=site:app
export FLASK_ENV=development

flask run -h 0.0.0.0 -p "${1:-8080}"