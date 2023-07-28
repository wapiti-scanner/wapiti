#!/bin/bash

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

cd "$(dirname "$0")"

if [[ $# -eq 0 ]]; then
    mapfile -t modules_dirs < <(find .test -maxdepth 1 -mindepth 1 -type d)
else
    tests=$*
    mapfile -t modules_dirs < <(echo -e "${tests// /\\n}" | sed 's/^/.test\//')  
fi

for module in "${modules_dirs[@]}";do
    if [[ -d "./$(basename "${module}")/assertions" ]]; then
        cp "${module}/"* "./$(basename "${module}")/"
        mapfile -t assertion_files < <(find "./$(basename "${module}")/" -name "*.out")
        for assertion_file in "${assertion_files[@]}";do
            mv -- "${assertion_file}" "$(dirname "${assertion_file}")/assertions/$(basename "${assertion_file}" .out).json"
        done
        echo "assertions of module $(basename "${module}") copied"
    else 
        echo "directory ./$(basename "${module}")/assertions/ does not exist, skipping..."
    fi 
done
