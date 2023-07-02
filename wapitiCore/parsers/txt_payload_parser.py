from typing import Iterator

from wapitiCore.model import PayloadInfo


def process_line(line: str):
    clean_line = line.strip(" \n")
    clean_line = clean_line.replace("[TAB]", "\t")
    clean_line = clean_line.replace("[LF]", "\n")
    clean_line = clean_line.replace("[FF]", "\f")  # Form feed
    clean_line = clean_line.replace("\\0", "\0")

    return clean_line


class TxtPayloadReader:
    """Class for reading and writing in text files"""

    def __init__(self, txt_file: str):
        self._txt_file = txt_file
        self.handlers = []

    def add_handler(self, func):
        self.handlers.append(func)

    def __iter__(self) -> Iterator[PayloadInfo]:
        try:
            with open(self._txt_file, errors="ignore", encoding='utf-8') as file:
                for line in file:
                    clean_line = process_line(line)
                    for handler in self.handlers:
                        clean_line = handler(clean_line)
                    yield PayloadInfo(payload=clean_line)
        except IOError as exception:
            print(exception)
