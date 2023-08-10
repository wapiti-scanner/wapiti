#!/bin/bash

TEMPLATE_DOCKER_COMPOSE_FILE='
version: '\''3.9'\''

# Use the shortcuts you need and remove unused ones
x-default_php_setup:
  &default_php_setup
  image: php${PHP_HASH}
  networks:
    - test-network

x-healthcheck_web:
  &healthcheck_web
  healthcheck:
    test: ${DEFAULT_WEB_HEALTHCHECK_COMMAND}
    interval: ${DEFAULT_HEALTHCHECKS_INTERVAL}
    timeout: ${DEFAULT_HEALTHCHECKS_TIMEOUT}
    start_period: ${DEFAULT_HEALTHCHECKS_START_PERIOD}
    retries: ${DEFAULT_HEALTHCHECKS_RETRIES}

x-default_mysql_setup:
  &default_mysql_setup
  image: mysql${MYSQL_HASH}
  networks:
    - test-network

x-healthcheck_mysql:
  &healthcheck_mysql
  healthcheck:
    test: ${DEFAULT_MYSQL_HEALTHCHECK_COMMAND}
    start_period: ${DEFAULT_HEALTHCHECKS_START_PERIOD}
    interval: ${DEFAULT_HEALTHCHECKS_INTERVAL}
    timeout: ${DEFAULT_HEALTHCHECKS_TIMEOUT}
    retries: ${DEFAULT_HEALTHCHECKS_RETRIES}

services:
  # Enter your services here
  INT_TEST_NAME:
    #build:
    #  context: ./test_INT_TEST_NAME/
    #  dockerfile: Dockerfile
    #  args:
    #   PHP_HASH_TAG: ${PHP_HASH}
    #<<: *healthcheck_web
    #networks:
    #  - test-network
    #
    # or 
    #
    #<< [ *default_php_setup, *healthcheck_web]
    volumes:
      - ./test_INT_TEST_NAME/php/src:/var/www/html



  # Wapiti container 
  wapiti:
    build:
      context: "../../"
      dockerfile: "./tests/integration/wapiti/Dockerfile.integration"
      no_cache: true
    container_name: wapiti
    volumes:
      - ./.test:/home/
    networks:
      - test-network
    command: "${TESTS}"
    depends_on:
      INT_TEST_NAME:
        condition: service_healthy
      # Don'\''t forget dependencies

networks:
  test-network:
';

TEMPLATE_BEHAVIOR_FILE='{
    "INT_TEST_NAME":{
        "modules": "",
        "supplementary_argument": "",
        "report_filter_tree": {},
        "targets":[
            {
                "name": ""
            }
        ]
    }
}';


# exit upon any error
set -o errexit;

# exit upon using undeclared variables
set -o nounset;

# Placing ourselves in the right directory
cd "$(dirname "$0")";

# Checking part:
# check if any test must be created
if (( ${#@} == 0 )); then
    echo "no iteration test provided";
    exit 1;
fi

# Iterating through tests to check them 
all_tests="$(find . -maxdepth 1 -type d -name "test_*" -printf "%P ")"
declare -A uniqueness
for arg in "$@"; do
    if [[ ! "$arg" =~ ^"test_".* ]]; then
      echo "integration test name of \"${arg}\" not conform";
      exit 1;
    elif [[ "$all_tests" =~ .*"$arg".* ]];then
      # Checking if any test name already exist
      echo "integration test \"${arg}\" already exist";
      exit 1;
    elif [[ -v uniqueness[$arg] ]]; then
      echo "duplicate arg $arg"
      exit 1;
    fi
    uniqueness[$arg]=
done
# End of checking part

# Iterating through tests to create 
for arg in "$@"; do
    mkdir -p "${arg}/assertions";
    ln -s ../../check.sh "${arg}/assertions/check.sh";
    mkdir -p "${arg}/php/src";
    echo "${TEMPLATE_BEHAVIOR_FILE//INT_TEST_NAME/${arg}}" > "${arg}/behavior.json";
    echo "${TEMPLATE_DOCKER_COMPOSE_FILE//INT_TEST_NAME/${arg#test_}}" > "${arg}/docker-compose.setup.yml";
done; 