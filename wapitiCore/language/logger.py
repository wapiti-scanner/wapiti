#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2017-2020 Nicolas Surribas
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
import sys
from abc import abstractmethod


class BaseLogger:
    def __init__(self):
        self._verbose = 0

    @property
    def verbose(self):
        return self._verbose

    @verbose.setter
    def verbose(self, value: int):
        self._verbose = value

    @abstractmethod
    def log(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_red(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_green(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_yellow(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_cyan(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_white(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_magenta(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_blue(self, fmt_string, *args):
        pass

    @abstractmethod
    def log_orange(self, fmt_string, *args):
        pass


class ConsoleLogger(BaseLogger):
    # Color codes
    STD = "\033[0;0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    ORANGE = "\033[0;33m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    GB = "\033[0;30m\033[47m"

    def __init__(self):
        super().__init__()
        self._color = False

    @property
    def color(self):
        return self._color

    @color.setter
    def color(self, value: bool):
        self._color = value

    def log(self, fmt_string, *args):
        if len(args) == 0:
            print(fmt_string)
        else:
            print(fmt_string.format(*args))
        if self.color:
            sys.stdout.write(self.STD)

    def log_red(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.RED)
        self.log(fmt_string, *args)

    def log_green(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.GREEN)
        self.log(fmt_string, *args)

    def log_yellow(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.YELLOW)
        self.log(fmt_string, *args)

    def log_cyan(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.CYAN)
        self.log(fmt_string, *args)

    def log_white(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.GB)
        self.log(fmt_string, *args)

    def log_magenta(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.MAGENTA)
        self.log(fmt_string, *args)

    def log_blue(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.BLUE)
        self.log(fmt_string, *args)

    def log_orange(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.ORANGE)
        self.log(fmt_string, *args)
