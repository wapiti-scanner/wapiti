#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2017-2023 Nicolas Surribas
# Copyright (C) 2024 Cyberwatch
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

# Wapiti relies on httpxyz, a maintained fork of httpx, to work around unfixed httpx bugs
# (notably the loss of the Location header on redirect responses carrying an invalid URL when
# follow_redirects=False, see https://github.com/wapiti-scanner/wapiti/issues/690 and #786).
# Importing httpcorexyz/httpxyz here registers them as "httpcore"/"httpx" in sys.modules so that
# every subsequent "import httpx" (in Wapiti and in third-party libraries such as httpx-ntlm and
# mitmproxy) transparently resolves to the fork. This must happen before anything imports httpx,
# hence its placement at the very top of the package.
import httpcorexyz  # noqa: F401  pylint: disable=unused-import,wrong-import-position
import httpxyz  # noqa: F401  pylint: disable=unused-import,wrong-import-position

parser_name = "html.parser"
WAPITI_VERSION = "3.3.0"
