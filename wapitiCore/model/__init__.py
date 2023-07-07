from typing import List, Callable, Iterable, Union


# Modules using an INI file with payloads have their own PayloadInfo class generated dynamically
# This one is for other modules and to help annotation
class PayloadInfo:
    payload: str
    rules: List[str]
    injection_type: str

    def __init__(self, payload: str, **kwargs):  # pylint: disable=unused-argument
        self.payload = payload


PayloadCallback = Callable[[], Iterable[PayloadInfo]]
PayloadSource = Union[List[PayloadInfo], PayloadCallback]


def str_to_payloadinfo(payloads: List[str]) -> List[PayloadInfo]:
    return [PayloadInfo(payload=string) for string in payloads]
