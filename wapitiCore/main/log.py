#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2006-2021 Nicolas SURRIBAS
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
from functools import partial

from loguru import logger as logging

logging.remove()

# Setup additional logging levels, from the less important to the more critical
# Each attempted mutated request will be logged as VERBOSE as it generates a lot of output
# Each attacked original request will be logged as INFO
# Others info like currently used attack module must be logged even in quiet mode so BLUE level must be used as least

# logging.debug is level 10, this is the value defined in Python's logging module and is reused by loguru
logging.level("VERBOSE", no=15)
# logging.info is 20
logging.level("BLUE", no=21, color="<blue>")
logging.level("GREEN", no=22, color="<green>")
# logging.success is 25
# logging.warning is 30
logging.level("ORANGE", no=35, color="<yellow>")
# logging.error is 40
logging.level("RED", no=45, color="<red>")
# logging.critical is 50

log_blue = partial(logging.log, "BLUE")
log_green = partial(logging.log, "GREEN")
log_red = partial(logging.log, "RED")
log_orange = partial(logging.log, "ORANGE")
log_verbose = partial(logging.log, "VERBOSE")

# Set default logging
logging.add(sys.stdout, colorize=False, format="{message}", level="INFO")
