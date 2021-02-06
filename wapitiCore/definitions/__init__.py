import pkgutil
from os.path import dirname
from typing import List, Dict

additionals = []
anomalies = []
vulnerabilities = []

for __, modname, ___ in pkgutil.iter_modules([dirname(__file__)], prefix=__package__ + "."):
    module = __import__(modname, fromlist="dummy")
    if module.TYPE == "additional":
        additionals.append(module)
    elif module.TYPE == "anomaly":
        anomalies.append(module)
    elif module.TYPE == "vulnerability":
        vulnerabilities.append(module)


def flatten_references(references: List) -> Dict:
    result = {}
    for reference in references:
        result[reference["title"]] = reference["url"]
    return result
