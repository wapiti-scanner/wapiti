#!/bin/bash

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

cd "$(dirname "$0")"

mapfile -t modules_dirs < <(find .test -maxdepth 1 -mindepth 1 -type d)

for module in "${modules_dirs[@]}";do
    if [[ -d "./$(basename "${module}")/assertions" ]]; then
        cp "${module}/"* "./$(basename "${module}")/"
        mapfile -t assertion_files < <(find "./$(basename "${module}")/" -name "*.out")
        for assertion_file in "${assertion_files[@]}";do
            mv -- "${assertion_file}" "$(dirname "${assertion_file}")/assertions/$(basename "${assertion_file}" .out).json"
        done
        echo "assertions of module $(basename "${module}") copied"
    else 
        echo "directory ./$(basename "${module}")/ does not exist, skipping..."
    fi 
done

# sudo rm -rf ./.test/*

