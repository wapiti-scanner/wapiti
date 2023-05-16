#!/bin/bash

docker compose -f docker-compose.setup.yml up --abort-on-container-exit 

# will do some checks only where assertions files exist
asserters=$(find . -mindepth 2 -type d -name assertions)

for path in ${asserters}; do
    cd  "${path}"
    bash "check.sh"
    cd - > /dev/null
done
