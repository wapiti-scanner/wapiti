#!/bin/bash

# List of modules to be tested
TESTS="test_crawler_auth \
test_crawler_redirect \
test_mod_backup \
test_mod_brute_login_form \
test_mod_buster \
test_mod_cookieflags \
test_mod_crlf \
test_mod_csp \
test_mod_csrf \
test_mod_cms \
test_mod_htaccess \
test_mod_http_headers \
test_mod_https_redirect \
test_mod_ldap \
test_mod_exec \
test_mod_file \
test_mod_log4shell \
test_mod_methods \
test_mod_permanentxss \
test_mod_redirect \
test_mod_shellshock \
test_mod_ssrf \
test_mod_sql \
test_mod_timesql \
test_mod_wapp \
test_mod_wp_enum \
test_mod_xss \
test_mod_xxe"

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

# Placing ourselves in the right directory
cd "$(dirname "$0")"

function cleanup(){
    rm -f "$(dirname "$0")"/.docker-compose.final.yml
    rm -f "$(dirname "$0")"/wapiti/behavior.json
}

# Cleaning temporary files on any signal
trap cleanup INT EXIT

# Parsing script arguments 
declare -A args
for arg in "$@"; do
    args[$arg]=1;
done; 

if [[ -v args[--help] ]]; then
    # Printing some help
    printf "%s\n" \
           "Entrypoint to run integration tests" \
           "Usage: ./run.sh [options]" \
           "Options:" \
           "    --help              Display this message and exit"\
           "    --docker-clean      Kill containers, remove and prune all docker images, volumes, and system, be carefull when using this option"\
           "    --verbose-build     Print the build messages before running the tests"\
           "    --debug-containers  Attach all containers to the STDOUT";
           exit 0;
fi



# Check if TESTS variable is well set, look for all tests otherwise
if [[ ! -v TESTS ]]; then
    TESTS=$(find . -maxdepth 1 -type d -name "test_*" -printf "%P " | xargs)
fi
readarray -d ' ' -t TESTS_ARRAY <<< "${TESTS}"
export TESTS

# Building the parameters for docker
declare -a DOCKER_COMPOSE_CONFIG_ARGUMENT
declare -a DOCKER_COMPOSE_UP_ARGUMENT
for test in "${TESTS_ARRAY[@]}"; do
    # removing unwanted newlines because last item has one (why ??)
    DOCKER_COMPOSE_CONFIG_ARGUMENT+=("-f ./${test//$'\n'/}/docker-compose.setup.yml")
done
if [[ -v args[--debug-containers] ]]; then
    DOCKER_COMPOSE_UP_ARGUMENT+=("up --abort-on-container-exit")
else 
    DOCKER_COMPOSE_UP_ARGUMENT+=("up -d")
fi

# Generating global docker compose file 
docker compose --env-file .env --project-directory ./ ${DOCKER_COMPOSE_CONFIG_ARGUMENT[*]} config -o .docker-compose.final.yml
# Generating global json file (doesn't matter if all the tests are inside, the $TESTS variable handle what to attack)
jq -s 'add' ./*/behavior.json > ./wapiti/behavior.json

if [[ -v args[--docker-clean] ]]; then
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
docker network inspect test-network &> /dev/null || docker network create test-network &> /dev/null

# Shellcheck says to quote the ${DOCKER_COMPOSE_UP_ARGUMENT}
# ignore that or the stat command invoked by docker will break

# Building containers
if [[ ! -v args[--verbose-build] ]]; then
    docker compose -f .docker-compose.final.yml build --quiet
    DOCKER_COMPOSE_UP_ARGUMENT+=("--quiet-pull")
else
    docker compose -f .docker-compose.final.yml build
fi

# Start the tests
echo "waiting for healthchecks to start Wapiti"
docker compose --progress quiet --project-directory ./ -f .docker-compose.final.yml ${DOCKER_COMPOSE_UP_ARGUMENT[*]} 

if [[ ! -v args[--debug-containers] ]]; then
    echo "Wapiti container ready, attaching"
    docker attach "$(docker ps -aq --filter name=wapiti)"
fi

EXIT_CODE=0
for test in "${TESTS_ARRAY[@]}"; do
    cd "${test//$'\n'/}/assertions/" 
    bash "check.sh" | tee -a ../../.dump_diff_file.txt
    # Workaround to check if check.sh succeed, may not work on zsh 
    if [[ "${PIPESTATUS[0]}" -eq 1 ]]; then
        EXIT_CODE=1
    fi
    cd - > /dev/null 
done

exit $EXIT_CODE
