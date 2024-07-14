import pkgutil
from os.path import dirname
from typing import List, Dict, Type

from wapitiCore.definitions.base import FindingBase

additionals: List[Type[FindingBase]] = []
anomalies: List[Type[FindingBase]] = []
vulnerabilities: List[Type[FindingBase]] = []

for __, modname, ___ in pkgutil.walk_packages(path=[dirname(__file__)], prefix="wapitiCore.definitions."):
    module = __import__(modname, fromlist="dummy")
    for item_name in dir(module):
        if item_name.startswith("_") or item_name == "FindingBase":
            continue

        item = getattr(module, item_name)
        if isinstance(item, type) and issubclass(item, FindingBase):
            if item.type() == "additional":
                additionals.append(item)
            elif item.type() == "anomaly":
                anomalies.append(item)
            elif item.type() == "vulnerability":
                vulnerabilities.append(item)


def flatten_references(references: List) -> Dict:
    result = {}
    for reference in references:
        result[reference["title"]] = reference["url"]
    return result
