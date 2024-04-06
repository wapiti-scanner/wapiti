from typing import Generator, List, Union


def find_injectable(parents: List[str], obj) -> Generator[List[Union[str, int]], None, None]:
    if isinstance(obj, (str, int)):
        yield parents
    elif isinstance(obj, list):
        # Only consider the first item in the list if not empty
        # We assume all objects in the list will be of identical type
        if len(obj):
            yield from find_injectable(parents + [0], obj[0])
        else:
            yield parents + [0]
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from find_injectable(parents + [k], v)


def set_item(json_object, injection_point, value):
    ptr = json_object
    for key in injection_point[:-1]:
        ptr = ptr[key]

    if isinstance(ptr, list) and not ptr:
        ptr.append(value)
    else:
        ptr[injection_point[-1]] = value


def get_item(json_object, path):
    if not path:
        return json_object

    ptr = json_object
    for key in path[:-1]:
        ptr = ptr[key]

    try:
        return ptr[path[-1]]
    except (KeyError, IndexError):
        pass

    return ptr
