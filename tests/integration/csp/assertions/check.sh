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

# get all the assertions (paths to text files that we want to find in the report)
# 1 assertion per target, one or more targets per module
# assertions can be found in the same directory than this file
declare -a assertions=()
mapfile -t assertions < <(find . -name "*.txt")
if [[ ${#assertions[@]} -eq 0 ]]; then 
    die "Error: No assertions found in module $MODULE_NAME"
fi

# Since the assertions and the target reports must have the same name 
# (except their extention names, .txt and .out) we extract the targets names
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

# Comparing outputs and assertions is a 2-steps process:
for i in "${!outputs[@]}"; do
    # First, we get rid of the beginning of the output by finding 
    # The first common line between the assertion and the output
    mapfile -t assertion_content < "${assertions[$i]}"

    common_line_nbr=$(grep -n -m 1 "${assertion_content[0]}" "${outputs[$i]}" | cut -d ":" -f 1)
    # Cut the top of the output to the top of the assertions and 
    # removing the dates of the output so we only get relevant things
    declare -a relevant_output
    readarray -t relevant_output <<< "$(tail -n +"$common_line_nbr" "${outputs[$i]}" | grep -v "\"date\"")"

    # Then we compare the filtered output content with the assertion
    if [[ "${relevant_output[*]}" == "${assertion_content[*]}" ]]; then
        # The test pass
        echo "Assertion ${targets_name[$i]} of module $MODULE_NAME respected"
    else 
        # Or we have to dig down through the differences 
        # Lines that are in the output but not in the assertions
        echo "In module $MODULE_NAME, assertion ${targets_name[$i]}:"
        for line in "${relevant_output[@]}"; do
            if [[ ! "${assertion_content[*]}" =~ "$line" ]]; then
                echo "Line not expected: $line"
            fi
        done 
        # Lines that are in the assertion but not in the output
        for line in "${assertion_content[@]}"; do
            if [[ ! "${relevant_output[*]}" =~ "$line" ]]; then 
                echo "Line missing:      $line"
            fi 
        done 
    fi
done
exit 0
