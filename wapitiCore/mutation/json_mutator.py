import json
from os.path import splitext
from typing import Generator, List, Union, Iterator, Tuple

from wapitiCore.attack.attack import Parameter, ParameterSituation
from wapitiCore.model import PayloadInfo, PayloadSource
from wapitiCore.net import Request


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


class JSONMutator():
    """The JSONMutator will only mutate the JSON object within the body,
    it won't change parameters in the query string"""
    def __init__(
            self, _methods="FGP", _qs_inject=False, _max_queries_per_pattern: int = 1000,
            _skip=None  # Must not attack those parameters (blacklist)
    ):
        self._attack_hashes = set()

    @staticmethod
    def mutate(request: Request,
               payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        get_params = request.get_params

        referer = request.referer

        if not request.is_json:
            return

        try:
            data = json.loads(request.post_params)
        except json.JSONDecodeError:
            return

        injection_points = find_injectable([], data)

        for path in injection_points:
            saved_value = get_item(data, path)

            iterator = payloads if isinstance(payloads, list) else payloads()
            payload_info: PayloadInfo
            for payload_info in iterator:
                raw_payload = payload_info.payload

                # We will inject some payloads matching those keywords whatever the type of the object to overwrite
                if ("[FILE_NAME]" in raw_payload or "[FILE_NOEXT]" in raw_payload) and not request.file_name:
                    continue

                # no quoting: send() will do it for us
                raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                if isinstance(request.path_id, int):
                    raw_payload = raw_payload.replace("[PATH_ID]", str(request.path_id))

                # We don't want to replace certain placeholders reusing the current value if that value is not a string
                if any(pattern in raw_payload for pattern in ("[EXTVALUE]", "[DIRVALUE]")):
                    if not isinstance(saved_value, str):
                        continue

                    if "[EXTVALUE]" in raw_payload:
                        if "." not in saved_value[:-1]:
                            # Nothing that looks like an extension, skip the payload
                            continue
                        raw_payload = raw_payload.replace("[EXTVALUE]", saved_value.rsplit(".", 1)[-1])

                    raw_payload = raw_payload.replace("[DIRVALUE]", saved_value.rsplit('/', 1)[0])

                if "[VALUE]" in raw_payload:
                    if not isinstance(saved_value, (int, str)):
                        continue

                    raw_payload = raw_payload.replace("[VALUE]", str(saved_value))

                set_item(data, path, raw_payload)

                evil_req = Request(
                    request.path,
                    method=request.method,
                    enctype="application/json",
                    get_params=get_params,
                    post_params=json.dumps(data),
                    referer=referer,
                    link_depth=request.link_depth
                )
                payload_info.payload = raw_payload
                yield evil_req, Parameter(
                    name=".".join([str(key) for key in path]),
                    situation=ParameterSituation.JSON_BODY
                ), payload_info
                # put back the previous value
                set_item(data, path, saved_value)
