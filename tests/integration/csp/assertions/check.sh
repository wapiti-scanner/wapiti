#!/bin/bash

# exit upon any error
set -o errexit

# exit upon using undeclared variables
set -o nounset

die(){
    echo >&2 "$@"
    exit 1
}

MODULE_NAME=$(pwd | cut -d'/' -f8)

# Get all the assertions (paths to text files that we want to find in the report)
# 1 assertion per target, one or more targets per module
# assertions can be found in the same directory than this file
declare -a assertions=()
mapfile -t assertions < <(find . -name "*.txt")
if [[ ${#assertions[@]} -eq 0 ]]; then 
    die "Error: No assertions found in module $MODULE_NAME"
fi

# Since the assertions and the target reports must have the same name 
# (except their extention name, .txt and .out) we extract the target names
# from the assertion array
# We also use their names to log some informations so keeping an array is
# somewhat useful
declare -a targets_name
for i in "${assertions[@]}"; do
    filename="$(basename "$i")"
    targets_name+=("${filename%.*}")
done


# We store the target reports paths in an array with respect to the target_name 
# array order 
# That way, our third array is ordered with the 2 other ones and we can safely 
# use indexes to compare
declare -a outputs
for i in "${targets_name[@]}"; do
    outputs+=("$(find ../../.test/"$MODULE_NAME"/ -name "$i.out")")
done
if [[ ${#outputs[@]} -eq 0 ]]; then 
    die "Error: No targets found in module $MODULE_NAME"
fi

# A special case is if we don't get the same number of reports as they are targets
# Wapiti may not detect some targets or it can be due to various misconfigurations
# So we check the size of each array to be sure they match
if [[ ${#assertions[@]} -ne ${#targets_name[@]} || ${#targets_name[@]} -ne ${#outputs[@]} ]] ; then
    die "Error: different number of reports/assertion files, found ${#outputs[@]} outputs for ${#assertions[@]} assertions"
fi

# Finally, we give grep the 2 paths to know weither an assertion's content is 
# a substring of the report or not 
for i in "${!outputs[@]}"; do
    if [[ $( grep -Ff <(cat "${assertions[$i]}") <(cat "${outputs[$i]}") >/dev/null ) -ne 0 ]]; then
        die "Assertion ${targets_name[$i]} not respected"
    else
        echo "Assertion ${targets_name[$i]} of module $MODULE_NAME respected"
    fi
done

exit 0
