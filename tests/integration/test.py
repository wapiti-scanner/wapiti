import json
import os
import sys
import requests
import re
from itertools import cycle

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

# Running wapiti for each module for each target
# If a target isn't set up, passing to another and so on
# That way we don't have a strict order and spare testing time
for mod in iter_modules:
    if len(tested_targets) == total_targets:
        break
    for target in mod["targets"]:
        if target not in tested_targets:
            sys.stdout.write(f"Querying target {target}...\n")
            # print(f"Querying target {target}...")
            try:
                requests.get(f"http://{target}")
                os.system(f"wapiti -u http://{target} -m {mod['module']} "
                          f"-f json -o /home/{mod['module']}/{re.sub('/','_',target)}.out"
                          f" --flush-session")
                tested_targets.add(target)
            except requests.exceptions.ConnectionError:
                sys.stdout.write(f"Target {target} is not ready yet...\n")
                # print(f"Target {target} is not ready yet...")
                pass
