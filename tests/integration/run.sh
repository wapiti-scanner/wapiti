#!/bin/bash

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

docker compose -f docker-compose.setup.yml up --abort-on-container-exit 

# will do some checks only where assertions files exist
declare -a asserters=()
mapfile -t asserters < <(find . -mindepth 2 -type d -name assertions)

for path in "${asserters[@]}"; do
    cd "${path}" 
    bash "check.sh"
    cd - > /dev/null 
done
