from configparser import ConfigParser
from collections import defaultdict
from dataclasses import make_dataclass
import typing

from wapitiCore.model import PayloadInfo


def convert_string_to_builtin(value: str) -> typing.Any:
    if value.lower() in ("no", "false"):
        return False
    if value.lower() in ("yes", "true"):
        return True
    if value.lower() in ("none", "null"):
        return None
    return value


def replace_tags(payload: str) -> str:
    clean_line = payload.strip(" \n")
    clean_line = clean_line.replace("[TAB]", "\t")
    clean_line = clean_line.replace("[LF]", "\n")
    clean_line = clean_line.replace("[FF]", "\f")  # Form feed
    clean_line = clean_line.replace("[NULL]", "\0")
    return clean_line


class IniPayloadReader:
    def __init__(self, ini_file: str):
        self.config_reader = ConfigParser(interpolation=None)
        self.payload_class = None
        self.current_index = 0

        with open(ini_file, 'r', encoding='utf-8') as file_data:
            self.config_reader.read_file(file_data)

        self.payload_class = make_dataclass("PayloadInfo", self.config_reader["DEFAULT"].keys())
        self.sections = iter(self.config_reader.sections())
        self.key_handlers = defaultdict(list)

    def add_key_handler(self, key, func):
        self.key_handlers[key].append(func)

    def get(self, section_name):
        items = {}
        for key, value in self.config_reader[section_name].items():
            value = convert_string_to_builtin(value)
            for handler in self.key_handlers[key]:
                value = handler(value)
            items[key] = value

        return self.payload_class(**items)

    def __iter__(self) -> typing.Iterator[PayloadInfo]:
        for section in self.sections:
            yield self.get(section)
