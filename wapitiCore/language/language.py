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
import os
import locale
import gettext
import sys

AVAILABLE_LANGS = ["en", "es", "fr", "pt", "zh"]  # "de", "ms"]

if sys.platform == "win32":
    import ctypes

    windll = ctypes.windll.kernel32
    def_locale = locale.windows_locale[windll.GetUserDefaultUILanguage()]  # for example fr_FR
    lang_country = def_locale[:2]
else:
    # getdefaultlocale will return (None, None) if locale settings are incorrectly set (ex: LANG=C)
    def_locale = locale.getdefaultlocale()  # for example ('fr_FR', 'cp1252')
    lang_country = def_locale[0]

lang = None
if isinstance(lang_country, str) and len(lang_country) >= 2:
    lang = lang_country[:2]  # fr

if lang is None:
    print("Unable to correctly determine your language settings. Using english as default.")
    print("Please check your locale settings for internationalization features.")
    print("===============================================================")
    lang = "en"
elif lang not in AVAILABLE_LANGS:
    # if lang is not one of the supported languages, we use english
    print("Oops! No translations found for your language... Using english.")
    print("Please send your translations for improvements.")
    print("===============================================================")
    lang = "en"

BASE_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)
LANG_PATH = os.path.join(BASE_DIR, "config", "language")

lan = gettext.translation(
    "wapiti",
    LANG_PATH,
    languages=[lang, "en"],
    codeset="UTF-8"
)
_ = lan.gettext
