from typing import Dict
from unittest.mock import mock_open, MagicMock


class AsyncIterator:
    def __init__(self, seq):
        self.iter = iter(seq)

    def __aiter__(self):
        return self

    def __call__(self, *args, **kwds):
        return self

    async def __anext__(self):
        try:
            return next(self.iter)
        except StopIteration:
            raise StopAsyncIteration


def get_mock_open(files: Dict[str, str]):
    def open_mock(filename, *_args, **_kwargs):
        for expected_filename, content in files.items():
            if filename == expected_filename:
                return mock_open(read_data=content).return_value
        raise FileNotFoundError('(mock) Unable to open {filename}')
    return MagicMock(side_effect=open_mock)
