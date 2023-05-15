#!/bin/bash

docker compose -f docker-compose.solo_test.yml up --abort-on-container-exit

asserters=$(find . -name check.sh)

for script in ${asserters}; do
    cd $(dirname "${script}")
    bash $(basename "${script}")
    cd - > /dev/null
done
