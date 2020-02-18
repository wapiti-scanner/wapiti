#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
#
# Original author :
# David del Pozo
# Alberto Pastor
# Copyright (C) 2008 Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
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

from wapitiCore.report.reportgeneratorinfo import ReportGeneratorInfo


class ReportGeneratorsXMLParser:

    REPORT_GENERATOR = "reportGenerator"
    REPORT_GENERATOR_KEY = "reportTypeKey"
    REPORT_GENERATOR_CLASS_MODULE = "classModule"
    REPORT_GENERATOR_CLASSNAME = "className"

    def __init__(self):
        self._parser = expat.ParserCreate()
        self._parser.StartElementHandler = self.start_element
        self._parser.EndElementHandler = self.end_element
        self._parser.CharacterDataHandler = self.char_data
        self.reportGenerators = []
        self.repGen = None
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
        if name == self.REPORT_GENERATOR:
            self.repGen = ReportGeneratorInfo()
        elif name == self.REPORT_GENERATOR_KEY:
            self.tag = self.REPORT_GENERATOR_KEY
        elif name == self.REPORT_GENERATOR_CLASSNAME:
            self.tag = self.REPORT_GENERATOR_CLASSNAME
        elif name == self.REPORT_GENERATOR_CLASS_MODULE:
            self.tag = self.REPORT_GENERATOR_CLASS_MODULE

    def end_element(self, name):
        if name == self.REPORT_GENERATOR:
            self.reportGenerators.append(self.repGen)

    def char_data(self, data):
        if self.tag == self.REPORT_GENERATOR_KEY:
            self.repGen.set_key(data)
        elif self.tag == self.REPORT_GENERATOR_CLASSNAME:
            self.repGen.set_class_name(data)
        elif self.tag == self.REPORT_GENERATOR_CLASS_MODULE:
            self.repGen.set_class_module(data)
        self.tag = ""

    def get_report_generators(self):
        return self.reportGenerators
