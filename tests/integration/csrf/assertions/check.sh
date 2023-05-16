#!/bin/bash
die(){
    echo >&2 "$@"
    exit 1
}


assertions=$(find . -name *.txt)

declare -a targets_name
for i in "${assertions}"; do
    targets_name+=($(basename $i | cut -d'.' -f 1))
done

declare -a outputs
for i in "${targets_name}"; do
    outputs+=($(find ../../.test/$(pwd | cut -d'/' -f8)/ -name "$i.out"))
done

if [[ ${#assertions[@]} -ne ${#targets_name[@]} || ${#targets_name[@]} -ne ${#outputs[@]} ]] ; then
    die "Error: different number of reports/assertion files, found ${#outputs[@]} outputs for ${#assertions[@]} assertions"
fi

for i in "${!outputs[@]}"; do
    grep -qFf <(cat "${assertions[$i]}") <(cat "${outputs[$i]}")
    if [[ $? -ne 0 ]]; then
        die "Assertion $targets_name[$i] not respected"
    else
        echo "Assertion ${targets_name[$i]} of module $(pwd | cut -d'/' -f8) respected"
    fi
done
