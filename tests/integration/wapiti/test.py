import json
import os
import sys
import requests
import re
from itertools import cycle
from collections import defaultdict
from itertools import chain
from time import sleep

from misc_functions import purge_irrelevant_data, filter_data, all_keys_dicts
from templates_and_data import DEFAULT_FILTER_TREE, EXISTING_MODULES, TREE_CHECKER

# parsing and checking the json file containing the modules
with open('/usr/local/bin/modules.json', 'r') as integration_file:
    integration_data = json.load(integration_file)
    assert set(chain.from_iterable([test["modules"].split(",")
               for _, test in integration_data.items()])).issubset(EXISTING_MODULES)

# Eventually filter arguments if any
if len(sys.argv) > 1:
    # first checking unknown tests/typo errors
    assert set(sys.argv[1:]).issubset(set(key for key, _ in integration_data.items()))
    # then filtering the wanted modules
    integration_data = {key: test for key, test in integration_data.items() if key in sys.argv[1:]}

# creating folders for the logs
for test_key, _ in integration_data.items():
    if not os.path.exists(f"/home/{test_key}"):
        os.mkdir(f"/home/{test_key}")

# All keys available in a general default report
# to check syntax of filters on the fly
KEYS_AVAILABLE = all_keys_dicts(TREE_CHECKER)

# data structures to count and cycle through targets
targets_done = set()
iter_tests = cycle(integration_data.items())
total_targets = sum([len(test["targets"]) for _, test in integration_data.items()])

# If any target recieve too many requests, it might not have
# started well, this is another way to fill the set to break
# the loop
requests_counter = defaultdict(int)
MAX_REQ = 100

# Running wapiti for each module for each target
# If a target isn't set up, passing to another and so on
# That way we don't have a strict order and spare testing time
for key_test, content_test in iter_tests:
    if len(targets_done) == total_targets:
        break
    for target in content_test["targets"]:
        if target not in targets_done:
            sys.stdout.write(f"Querying target {target}...\n")
            requests_counter[target] += 1
            try:
                requests.get(f"{target}", verify=False)
                # We then call wapiti on each target of each module, generating a detailed JSON report
                json_output_path = f"/home/{key_test}/{re.sub('/','_',re.sub(r'^https?://', '', target))}.out"
                os.system(f"wapiti -u {target} -m {content_test['modules']} "
                          f"-f json -o {json_output_path} "
                          f"{content_test.get('supplementary_argument', '')} "
                          f"--detailed-report --flush-session --verbose 2 ")
                # Now we reparse the JSON to get only useful tests informations:
                with open(json_output_path, "r") as bloated_output_file:
                    bloated_output_data = json.load(bloated_output_file)
                with open(json_output_path, "w") as output_file:

                    # is a filter_tree supplied for this test ?
                    if "report_filter_tree" in content_test and content_test["report_filter_tree"]:
                        filter_tree = content_test["report_filter_tree"]
                        # We look for key that CANNOT exist at all,
                        # not even with a full report
                        filter_keys = all_keys_dicts(filter_tree)
                        assert filter_keys.issubset(KEYS_AVAILABLE), \
                            f"Keys not existing at all: {(filter_keys|KEYS_AVAILABLE)-(filter_keys&KEYS_AVAILABLE)}"
                    else:
                        filter_tree = DEFAULT_FILTER_TREE

                    filtered_data = filter_data(bloated_output_data, filter_tree)

                    # Some dates and other non determinist data
                    # still exists somewhere in the detailed report
                    bloated_output_data.get("infos", {}).pop("date", None)
                    purge_irrelevant_data(filtered_data)

                    # Rewriting the file
                    json.dump(filtered_data, output_file, indent=4)
                targets_done.add(target)
            except requests.exceptions.ConnectionError:
                sys.stdout.write(f"Target {target} is not ready yet...\n")
                # 0.5 seconds penalty in case of no response to avoid requests spamming and being
                # too fast at blacklisting targets
                sleep(0.5)
            if requests_counter[target] > MAX_REQ:
                sys.stdout.write(
                    f"Target {target} from test {key_test} takes too long to respond\nSkipping...\n")
                targets_done.add(target)
