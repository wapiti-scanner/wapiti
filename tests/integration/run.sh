#!/bin/bash

# List of modules to be tested
TESTS="test_mod_buster \
test_mod_drupal_enum \
test_mod_wapp "

# Normalize spaces for shell substitution
if [[ ! -z "$TESTS" ]]; then
    export TESTS="$(echo "$TESTS" | xargs) "
fi

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

# Placing ourselves in the right directory
cd "$(dirname "$0")"

# Parsing script arguments 
declare -A args
for arg in "$@"; do
    args[$arg]=1;
done; 

if [[ -v args["--help"] ]]; then
    # Printing some help
    printf "%s\n" \
           "Entrypoint to run integration tests" \
           "Usage: ./run.sh [options]" \
           "Options:" \
           "    --help           Display this message and exit"\
           "    --docker-clean   Kill containers, remove and prune all docker images, volumes, and system, be carefull when using this option"\
           "    --verbose-build  Print the build messages before running the tests";
           exit 0;
fi

if [[ -v args["--docker-clean"] ]]; then
    # Cleaning docker
    echo "Cleaning docker..."
    docker kill $(docker ps -q) 2> /dev/null || echo "No containers to kill"
    docker container prune -f 2> /dev/null || echo "No containers to prune"
    docker volume prune -f 2> /dev/null || echo "No volumes to prune"
    docker volume rm $(docker volume ls -q) 2> /dev/null || echo "No volume to remove"
    docker rmi $(docker images -a -q) 2> /dev/null || echo "No images to remove"
    (docker system prune -f && docker network create test-network) 2> /dev/null || echo "No need to prune the system"
fi

# Fallback to create the test-network in case it doesn't exist
docker network inspect test-network > /dev/null || docker network create test-network > /dev/null

echo "Building images..."
if [[ ! -v args["--verbose-build"] ]];then
# Quietly build all Dockerfiles
docker compose -f docker-compose.setup.yml build --quiet
fi

# Start the tests
docker compose  --progress quiet -f docker-compose.setup.yml up --abort-on-container-exit

declare -a asserters=()
# If the TESTS env variable is supplied, we will only check the specified tests
if [[ ! -z "$TESTS" ]]; then
    # Assuming all the tests in the TESTS variable are well written and exist
    mapfile -t asserters < <(echo -e "${TESTS// /\/assertions\/check.sh\\n}" |  head -n -1)
else
    # Otherwise, we take all the tests
    mapfile -t asserters < <(find . -mindepth 2 -type l,f -name check.sh)
fi
EXIT_CODE=0
for path in "${asserters[@]}"; do
    cd "$(dirname "${path}")" 
    bash "check.sh" | tee -a ../../.dump_diff_file.txt
    # Workaround to check if check.sh succeed, may not work on zsh 
    if [[ "${PIPESTATUS[0]}" -eq 1 ]]; then
        EXIT_CODE=1
    fi
    cd - > /dev/null 
done

exit $EXIT_CODE
