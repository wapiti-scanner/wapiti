import json
import os
import sys
import requests
import re
from itertools import cycle
from collections import defaultdict

# parsing the json file containing the modules
with open('/usr/local/bin/modules.json', 'r') as modules_file:
    modules_data = json.load(modules_file)

# Eventually filter arguments if any
if len(sys.argv) > 1:
    # first checking unknown modules/typo errors
    assert set(sys.argv[1:]).issubset(set([mod["module"] for mod in modules_data]))
    # then filtering the wanted modules
    modules_data = [mod for mod in modules_data if mod["module"] in sys.argv[1:]]

# creating folders for the logs
for mod in modules_data:
    if not os.path.exists(f"/home/{mod['module']}"):
        os.mkdir(f"/home/{mod['module']}")

# data structures to count target and cycle through modules
tested_targets = set()
iter_modules = cycle(modules_data)
total_targets = sum([len(mod["targets"]) for mod in modules_data])

# If any target recieve too many requests, it might not have
# started well, this is another way to fill the set to break
# the loop
requests_counter = defaultdict(int)
MAX_REQ = 50

# Running wapiti for each module for each target
# If a target isn't set up, passing to another and so on
# That way we don't have a strict order and spare testing time
for mod in iter_modules:
    if len(tested_targets) == total_targets:
        break
    for target in mod["targets"]:
        if target not in tested_targets:
            sys.stdout.write(f"Querying target {target}...\n")
            requests_counter[target] += 1
            try:
                secure_conn = ("https"
                               if requests.get(f"http://{target}", allow_redirects=True, verify=False).url.startswith("https://")
                               else "http")
                # We then call wapiti on each target of each module, generating a detailed JSON report
                os.system(f"wapiti -u {secure_conn}://{target} -m {mod['module']} "
                          f"-f json -o /home/{mod['module']}/{re.sub('/','_',target)}.out"
                          f" --detailed-report --flush-session --verbose 2 ")
                # Now we reparse the JSON to get only useful tests informations:
                with open(f"/home/{mod['module']}/{re.sub('/','_',target)}.out", "r") as bloated_output_file:
                    bloated_output_data = json.load(bloated_output_file)
                with open(f"/home/{mod['module']}/{re.sub('/','_',target)}.out", "w") as output_file:
                    # The date is useless and creates false positive, removing it
                    dateless_info_data = bloated_output_data.get("infos", {}).copy()
                    dateless_info_data.pop("date", None)
                    json.dump({
                        "vulnerabilities": bloated_output_data.get("vulnerabilities", {}),
                        "anomalies": bloated_output_data.get("anomalies", {}),
                        "additionnals": bloated_output_data.get("additionnals", {}),
                        "infos": dateless_info_data
                    }, output_file, indent=4)
                tested_targets.add(target)
            except requests.exceptions.ConnectionError:
                sys.stdout.write(f"Target {target} is not ready yet...\n")
                pass
            if requests_counter[target] > MAX_REQ:
                sys.stdout.write(
                    f"Target {target} from module {mod['module']} takes too long to respond\nSkipping...\n")
                tested_targets.add(target)
