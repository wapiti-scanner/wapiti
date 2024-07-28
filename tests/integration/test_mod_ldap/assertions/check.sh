#!/bin/bash

# Symlink this file to each module so it can 
# check the assertions.

#define some colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # no colors

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

die(){
    echo >&2 "$@"
    exit 1
}

# Ensure we are on the good execution directory
cd "$(dirname "$0")"
MODULE_NAME=$(basename "$(realpath ..)")

# get all the assertions (paths to text files that we want to
# find in the report).
# 1 assertion per target, one or more targets per module,
# assertions can be found in the same directory than this file
declare -a assertions
mapfile -t assertions < <(find . -name "*.json")
if [[ ${#assertions[@]} -eq 0 ]]; then 
    die "Error: No assertions found in module ${MODULE_NAME}"
fi

# Since the assertions and the target reports must have the same name 
# (except their extention names, .json and .out), we extract the targets names
# from the assertion array. We also use their names to log some informations 
# so keeping an array is somewhat useful
declare -a targets_name
for i in "${assertions[@]}"; do
    targets_name+=("$(basename "$i" .json)")
done

# We store the target reports paths in an array with respect to the target_name 
# array order. That way, our third array is ordered with the 2 other ones and 
# we can safely use indexes to compare
declare -a outputs
for target in "${targets_name[@]}"; do
    outputs+=("$(realpath "../../.test/${MODULE_NAME}/${target}.out")")
done
if [[ ${#outputs[@]} -eq 0 ]]; then 
    die "Error: No targets found in module ${MODULE_NAME}"
fi

# A special case is if we don't get the same number of reports as they are targets.
# Wapiti may not detect some targets or it can be due to various misconfigurations
# so we check the size of each array to be sure they match
if [[ ${#assertions[@]} -ne ${#targets_name[@]} || ${#targets_name[@]} -ne ${#outputs[@]} ]] ; then
    die "Error: different number of reports/assertion files, found ${#outputs[@]} outputs for ${#assertions[@]} assertions"
fi

# Function to remove PHPSESSID from cookie in http_request
remove_phpsessid() {
    jq 'walk(
        if type == "object" and has("http_request") then
            .http_request |= gsub("cookie: PHPSESSID=[^;\\n]*;?"; "cookie: ")
        else
            .
        end
    )' "$1"
}

EXIT_CODE=0
# Comparing outputs and assertions :
for i in "${!outputs[@]}"; do
    processed_output=$(remove_phpsessid "${outputs[$i]}")
    processed_assertion=$(remove_phpsessid "${assertions[$i]}")
    if [[ "$processed_output" != "$processed_assertion" ]]; then
        echo -e "Assertion $(basename "${assertions[$i]}" .json) of module ${MODULE_NAME} is ${RED}not respected:${NC}"
        echo "< : assertion"
        echo "> : output"
        diff <(echo "$processed_output" | jq --sort-keys .) <(echo "$processed_assertion" | jq --sort-keys .) || echo "---End of diff of assertion $(basename "${assertions[$i]}" .json) module ${MODULE_NAME}---"
        EXIT_CODE=1
    else 
        echo -e "Assertion $(basename "${assertions[$i]}" .json) of module ${MODULE_NAME} is ${GREEN}respected${NC}"
    fi 
done

exit $EXIT_CODE
