import json

import pytest

from wapitiCore.attack.attack import Parameter, ParameterSituation, Mutator
from wapitiCore.model import str_to_payloadinfo, PayloadInfo
from wapitiCore.mutation.json_mutator import find_injectable, set_item, get_item
from wapitiCore.net import Request


@pytest.mark.parametrize(
    "obj, paths",
    [
        [
            [],
            [[0]],
        ],
        [
            {},
            [],
        ],
        [
            {"dict_with_string_value": "hello"},
            [["dict_with_string_value"]],
        ],
        [
            {"dict_with_int_value": 42},
            [["dict_with_int_value"]],
        ],
        [
            {
                "nested_dict": {
                    "list_of_dicts": [
                        {"a": "b"},
                    ],
                }
            },
            [["nested_dict", "list_of_dicts", 0, "a"]]
        ],
        [
            {
                "nested_dict": {
                    "list_of_words": ["hello", "world"]
                }
            },
            [["nested_dict", "list_of_words", 0]]
        ],
        [
            [
                {"a": "b"},
                {"c": "d"},
            ],
            [[0, "a"]],
        ],
        [
            {
                "nested_dict": {
                    "list_of_dicts": [
                        {
                            "a": "b",
                            "c": "d",
                        },
                    ],
                    "list_of_words": ["yolo"],
                    "empty_list": [],
                    "empty_dict": {},
                },
                "item_string": "hello",
            },
            [
                ['nested_dict', 'list_of_dicts', 0, 'a'],
                ['nested_dict', 'list_of_dicts', 0, 'c'],
                ['nested_dict', 'list_of_words', 0],
                ['nested_dict', 'empty_list', 0],
                ['item_string'],
            ],
        ],
        [
            [
                [
                    {"a": "b"}
                ],
                42
            ],
            [
                [0, 0, "a"],
            ],
        ]
    ],
    ids=[
        "empty list",
        "empty dict",
        "dict with string value",
        "dict with int value",
        "nested dict > list > dict",
        "nested dict > list",
        "nested list > dict",
        "nested complex",
        "nested list > list > dict",
    ]
)
def test_find_injectable(obj, paths):
    assert paths == list(find_injectable([], obj))


@pytest.mark.parametrize(
    "original, path, expected",
    [
        [
            {"a": "b"},
            ["a"],
            {"a": "Hello"},
        ],
        [
            ["a", "b"],
            [0],
            ["Hello", "b"],
        ],
        [
            [],
            [0],
            ["Hello"],
        ],
        [
            {
                "nested_dict": {
                    "list_of_dicts": [
                        {
                            "a": "b",
                            "c": "d",
                        },
                    ],
                },
            },
            ['nested_dict', 'list_of_dicts', 0, 'c'],
            {
                "nested_dict": {
                    "list_of_dicts": [
                        {
                            "a": "b",
                            "c": "Hello",
                        },
                    ],
                },
            },
        ],
        [
            [
                [
                    {"a": "b"}
                ],
                42
            ],
            [0, 0, "a"],
            [
                [
                    {"a": "Hello"}
                ],
                42
            ],
        ]
    ],
    ids=[
        "simple dict",
        "simple list",
        "empty list",
        "nested complex",
        "nested list",
    ],
)
def test_set_item(original, path, expected):
    set_item(original, path, "Hello")
    assert expected == original


@pytest.mark.parametrize(
    "obj, path, expected",
    [
        [
            [],
            [0],
            [],
        ],
        [
            {"a": "b"},
            ["a"],
            "b",
        ],
        [
            ["a", "b"],
            [0],
            "a",
        ],
        [
            {
                "nested_dict": {
                    "list_of_dicts": [
                        {
                            "a": "b",
                            "c": "d",
                        },
                    ],
                },
            },
            ['nested_dict', 'list_of_dicts', 0, 'c'],
            "d",
        ],
        [
            [[{"a": "b"}], 42],
            [0, 0, "a"],
            "b",
        ]
    ],
    ids=[
        "empty list",
        "simple dict",
        "simple list",
        "nested dict",
        "nested list",
    ]
)
def test_get_item(obj, path, expected):
    assert expected == get_item(obj, path)


def test_json_mutator_replace_values():
    mutator = Mutator()
    # We will ensure we can inject data inside a string value and an int value
    request = Request(
        "http://perdu.com/api/",
        enctype="application/json",
        post_params=json.dumps({"a": [{"c": "e"}], "f": 5})
    )

    expected = [
        ('{"a": [{"c": "eyolo"}], "f": 5}', Parameter(name='a.0.c', situation=ParameterSituation.JSON_BODY), "eyolo"),
        ('{"a": [{"c": "e"}], "f": "5yolo"}', Parameter(name='f', situation=ParameterSituation.JSON_BODY), "5yolo"),
    ]

    mutated_request: Request
    parameter: Parameter
    payload_info: PayloadInfo

    for i, (mutated_request, parameter, payload_info) in enumerate(mutator.mutate(
            request,
            lambda _, __: str_to_payloadinfo(["[VALUE]yolo"]),
    )):
        assert expected[i] == (mutated_request.post_params, parameter, payload_info.payload)
        assert mutated_request.is_json


def test_json_mutator_handle_list():
    mutator = Mutator()
    # We will ensure we can inject data inside a string value and an int value
    request = Request(
        "http://perdu.com/api/",
        enctype="application/json",
        post_params=json.dumps({"a": [4]})
    )

    expected = (
        '{"a": ["4yolo"]}',
        Parameter(name='a.0', situation=ParameterSituation.JSON_BODY),
        "4yolo"
    )

    mutated_request: Request
    parameter: Parameter
    payload_info: PayloadInfo

    mutated_request, parameter, payload_info = next(mutator.mutate(
            request,
            lambda _, __: str_to_payloadinfo(["[VALUE]yolo"]),
    ))
    assert expected == (mutated_request.post_params, parameter, payload_info.payload)
    assert mutated_request.is_json


def test_json_mutator_handle_empty_list():
    mutator = Mutator()
    # We will ensure we can inject data inside an empty list
    request = Request(
        "http://perdu.com/api/",
        enctype="application/json",
        post_params=json.dumps({"a": []})
    )

    expected = (
        '{"a": ["Hello there"]}',
        Parameter(name="a.0", situation=ParameterSituation.JSON_BODY),
        "Hello there"
    )

    mutated_request: Request
    parameter: Parameter
    payload_info: PayloadInfo

    mutations = mutator.mutate(
        request,
        # the first payload should be skipped as it attempts to reuse a valid that doesn't exist
        lambda _, __: str_to_payloadinfo(["[VALUE]yolo", "Hello there"]),
    )
    mutated_request, parameter, payload_info = next(mutations)
    assert expected == (mutated_request.post_params, parameter, payload_info.payload)
    assert mutated_request.is_json

    with pytest.raises(StopIteration):
        next(mutations)


def test_json_mutator_query_string():
    mutator = Mutator()
    # JSON requests having parameters in the query string should see those parameters fuzzed too
    request = Request(
        "http://perdu.com/api/?session=31337",
        enctype="application/json",
        post_params=json.dumps({"a": "yolo"})
    )

    mutated_request: Request
    parameter: Parameter
    payload_info: PayloadInfo

    mutated_requests = []
    for mutated_request, _, _ in mutator.mutate(
        request,
        # the first payload should be skipped as it attempts to reuse a valid that doesn't exist
        lambda _, __: str_to_payloadinfo(["Hello there"]),
    ):
        mutated_requests.append(mutated_request)

    assert len(mutated_requests) == 2

    # Following request went through _mutate_urlencoded_multipart
    assert mutated_requests[0].url == "http://perdu.com/api/?session=Hello%20there"
    assert mutated_requests[0].post_params == request.post_params
    # Make sure enctype is kept
    assert mutated_requests[0].enctype == "application/json"

    # Following request went through _mutate_json
    assert mutated_requests[1].url == "http://perdu.com/api/?session=31337"
    assert mutated_requests[1].post_params == json.dumps({"a": "Hello there"})
    assert mutated_requests[1].enctype == "application/json"
