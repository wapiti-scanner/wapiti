#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2013-2020 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from xml.parsers import expat

from wapitiCore.language.vulnerability import Anomaly


class AnomalyXMLParser:

    ANOMALY = "anomaly"
    ANOMALY_NAME = "name"
    ANOMALY_DESCRIPTION = "description"
    ANOMALY_SOLUTION = "solution"
    ANOMALY_REFERENCE = "reference"
    ANOMALY_REFERENCES = "references"
    ANOMALY_REFERENCE_TITLE = "title"
    ANOMALY_REFERENCE_URL = "url"

    def __init__(self):
        self._parser = expat.ParserCreate()
        self._parser.StartElementHandler = self.start_element
        self._parser.EndElementHandler = self.end_element
        self._parser.CharacterDataHandler = self.char_data
        self.anomalies = []
        self.anom = None
        self.references = {}
        self.title = ""
        self.url = ""
        self.tag = ""

    def parse(self, filename):
        with open(filename) as f:
            content = f.read()
            self.feed(content)

    def feed(self, data):
        self._parser.Parse(data, 0)

    def close(self):
        self._parser.Parse("", 1)
        del self._parser

    def start_element(self, name, attrs):
        if name == self.ANOMALY:
            self.anom = Anomaly()
            self.anom.set_name(attrs[self.ANOMALY_NAME])
        elif name == self.ANOMALY_DESCRIPTION:
            self.tag = self.ANOMALY_DESCRIPTION
        elif name == self.ANOMALY_SOLUTION:
            # self.tag = self.ANOMALY_SOLUTION
            self.anom.set_solution(attrs["text"])
        elif name == self.ANOMALY_REFERENCES:
            self.references = {}
        elif name == self.ANOMALY_REFERENCE:
            self.tag = self.ANOMALY_REFERENCE
        elif name == self.ANOMALY_REFERENCE_TITLE:
            self.tag = self.ANOMALY_REFERENCE_TITLE
        elif name == self.ANOMALY_REFERENCE_URL:
            self.tag = self.ANOMALY_REFERENCE_URL

    def end_element(self, name):
        if name == self.ANOMALY:
            self.anomalies.append(self.anom)
        elif name == self.ANOMALY_REFERENCE:
            self.references[self.title] = self.url
        elif name == self.ANOMALY_REFERENCES:
            self.anom.set_references(self.references)

    def char_data(self, data):
        if self.tag == self.ANOMALY_DESCRIPTION:
            self.anom.set_description(data)
#    elif self.tag==self.ANOMALY_SOLUTION:
#      self.anom.set_solution(data)
        elif self.tag == self.ANOMALY_REFERENCE_TITLE:
            self.title = data
        elif self.tag == self.ANOMALY_REFERENCE_URL:
            self.url = data
        self.tag = ""

    def get_anomalies(self):
        return self.anomalies
