#!/usr/bin/env bash

set -e
set -x

coverage run --source=app -m pytest --color=yes
coverage report --show-missing --skip-covered
coverage html --title "${@-coverage}"
