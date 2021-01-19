#!/usr/bin/env python3
from xml.parsers.expat import ParserCreate

from wapitiCore.language.vulnerability import Additional


class AdditionalXMLParser:

    ADDITIONAL = "additional"
    ADDITIONAL_NAME = "name"
    ADDITIONAL_DESCRIPTION = "description"
    ADDITIONAL_SOLUTION = "solution"
    ADDITIONAL_REFERENCE = "reference"
    ADDITIONAL_REFERENCES = "references"
    ADDITIONAL_REFERENCE_TITLE = "title"
    ADDITIONAL_REFERENCE_URL = "url"

    def __init__(self):
        self._parser = ParserCreate()
        self._parser.StartElementHandler = self.start_element
        self._parser.EndElementHandler = self.end_element
        self._parser.CharacterDataHandler = self.char_data
        self.additionals = []
        self.addition = None
        self.references = {}
        self.title = ""
        self.url = ""
        self.tag = ""

    def parse(self, filename):
        with open(filename) as file:
            content = file.read()
            self.feed(content)

    def feed(self, data):
        self._parser.Parse(data, 0)

    def close(self):
        self._parser.Parse("", 1)
        del self._parser

    def start_element(self, name, attrs):
        if name == self.ADDITIONAL:
            self.addition = Additional()
            self.addition.set_name(attrs[self.ADDITIONAL_NAME])
        elif name == self.ADDITIONAL_DESCRIPTION:
            self.tag = self.ADDITIONAL_DESCRIPTION
        elif name == self.ADDITIONAL_SOLUTION:
            # self.tag = self.ADDITIONAL_SOLUTION
            self.addition.set_solution(attrs["text"])
        elif name == self.ADDITIONAL_REFERENCES:
            self.references = {}
        elif name == self.ADDITIONAL_REFERENCE:
            self.tag = self.ADDITIONAL_REFERENCE
        elif name == self.ADDITIONAL_REFERENCE_TITLE:
            self.tag = self.ADDITIONAL_REFERENCE_TITLE
        elif name == self.ADDITIONAL_REFERENCE_URL:
            self.tag = self.ADDITIONAL_REFERENCE_URL

    def end_element(self, name):
        if name == self.ADDITIONAL:
            self.additionals.append(self.addition)
        elif name == self.ADDITIONAL_REFERENCE:
            self.references[self.title] = self.url
        elif name == self.ADDITIONAL_REFERENCES:
            self.addition.set_references(self.references)

    def char_data(self, data):
        if self.tag == self.ADDITIONAL_DESCRIPTION:
            self.addition.set_description(data)
#    elif self.tag==self.ADDITIONAL_SOLUTION:
#      self.addition.set_solution(data)
        elif self.tag == self.ADDITIONAL_REFERENCE_TITLE:
            self.title = data
        elif self.tag == self.ADDITIONAL_REFERENCE_URL:
            self.url = data
        self.tag = ""

    def get_additionals(self):
        return self.additionals
