from typing import List, Callable, Iterable, Union


# Modules using an INI file with payloads have their own PayloadInfo class generated dynamically
# This one is for other modules and to help annotations
class PayloadInfo:
    payload: str
    rules: List[str]

    def __init__(self, payload: str, **kwargs):  # pylint: disable=unused-argument
        self.payload = payload


PayloadCallback = Callable[[], Iterable[PayloadInfo]]
PayloadSource = Union[List[PayloadInfo], PayloadCallback]


def payloads_to_payload_callback(payloads: List[str]) -> PayloadCallback:
    def func() -> Iterable[PayloadInfo]:
        for payload in payloads:
            yield PayloadInfo(payload=payload)

    return func
