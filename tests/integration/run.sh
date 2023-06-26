#!/bin/bash

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

# Cleaning docker
docker container prune -f || echo "no containers to prune"
docker volume prune -f || echo "no volumes to prune"
docker rmi $(docker images -a -q) || echo "no images to remove"
(docker system prune -f && docker network create test-network) || echo "no need to prune the system"

time docker compose -f docker-compose.setup.yml up --abort-on-container-exit 

# will do some checks only where assertions files exist
declare -a asserters=()
mapfile -t asserters < <(find . -mindepth 2 -type d -name assertions)

for path in "${asserters[@]}"; do
    cd "${path}" 
    bash "check.sh" || echo "assertion ${path} not ready, skipping"
    cd - > /dev/null 
done
