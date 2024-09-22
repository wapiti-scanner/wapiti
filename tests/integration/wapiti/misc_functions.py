from collections import defaultdict
from re import findall, MULTILINE
from json import dumps


def purge_irrelevant_data(data) -> None:
    """
    Look recursively for any pattern matching a 2 length sized list with
    "date", "last-modified", "keep-alive" or "etag" in a dictionary containing lists,
    dictionaries, and other non-collections structures. Removing them because those
    datas can change from one test to another and aren't really relevant 
    """
    if isinstance(data, dict):
        for key in data.keys():
            purge_irrelevant_data(data[key])
    elif isinstance(data, list) and len(data) != 0:
        indexes_to_remove = []
        for i, item in enumerate(data):
            if isinstance(item, list) and len(item) == 2 and item[0] in ("date", "last-modified", "etag", "keep-alive"):
                indexes_to_remove.append(i)
            elif isinstance(item, dict) or (isinstance(item, list) and len(item) > 2):
                purge_irrelevant_data(item)
        for i in indexes_to_remove[::-1]:
            data.pop(i)
    else:
        return


def filter_data(data, filter):
    """
    Filter recursively data from report using a filter, is sensitive to report changes and don't check
    if the filter is correct.
    Make sure to write filter correctly or reinforce this function
    """
    # Another check, type based, also considering if filter and data order match
    assert (type(data) is type(filter)) or (type(data) is type(None)), \
        f"Mismatch content, filter element is {type(filter)} and data element is {type(data)}"
    if isinstance(data, dict):
        filtered_tree = defaultdict()
        for data_key, data_content in data.items():
            if data_key in filter:
                nested_content = \
                    filter[data_key] and (isinstance(filter[data_key], dict) or isinstance(filter[data_key], list))
                filtered_tree[data_key] = \
                    filter_data(data_content, filter[data_key]) if nested_content else data_content
        return dict(filtered_tree)
    elif isinstance(data, list) and filter:
        filtered_list = list()
        for element in data:
            filtered_list.append(filter_data(element, filter[0]))
        return filtered_list


def all_keys_dicts(data: dict) -> set:
    """
    Function to return a set of every keys in a nested dictionary  
    """
    return set(findall(r"^[ ]*\"(.+?)\"\s*:", dumps(data, indent=4), MULTILINE))


def sort_lists_in_dict(data):
    """
    Function that recursively sort every lists in a dictionary to normalize them  
    Mainly used because requests in the detailed reports aren't always in the same order 
    """
    if data:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    sort_lists_in_dict(data[key])
                elif isinstance(value, list):
                    sort_lists_in_dict(data[key])
                    # sort the array here
                    data[key] = sorted(data[key], key=str)
        elif isinstance(data, list):
            for item in data:
                sort_lists_in_dict(item)
