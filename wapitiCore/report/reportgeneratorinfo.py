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
from importlib import import_module


class ReportGeneratorInfo:

    def __init__(self):
        self.name = None
        self.class_name = None
        self.class_module = None

    def get_key(self):
        return self.name

    def get_class_module(self):
        return self.class_module

    def get_class_name(self):
        return self.class_name

    def set_key(self, name):
        self.name = name

    def set_class_module(self, class_module):
        self.class_module = class_module

    def set_class_name(self, class_name):
        self.class_name = class_name

    def create_instance(self):
        # module = __import__(self.get_class_module(), globals(), locals(), ['NoName'], -1)
        module = import_module("wapitiCore.report.{}".format(self.get_class_module()))
        generator_class = getattr(module, self.get_class_name())
        return generator_class()
