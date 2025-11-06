#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas SURRIBAS
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
from datetime import datetime
from random import choice

from wapitiCore import WAPITI_VERSION
from wapitiCore.main.log import log_yellow, log_blue
from wapitiCore.moon import phase


def print_banner():
    banners = [
        """
     __      __               .__  __  .__________
    /  \\    /  \\_____  ______ |__|/  |_|__\\_____  \\
    \\   \\/\\/   /\\__  \\ \\____ \\|  \\   __\\  | _(__  <
     \\        /  / __ \\|  |_> >  ||  | |  |/       \\
      \\__/\\  /  (____  /   __/|__||__| |__/______  /
           \\/        \\/|__|                      \\/""",
        """
     __    __            _ _   _ _____
    / / /\\ \\ \\__ _ _ __ (_) |_(_)___ /
    \\ \\/  \\/ / _` | '_ \\| | __| | |_ \\
     \\  /\\  / (_| | |_) | | |_| |___) |
      \\/  \\/ \\__,_| .__/|_|\\__|_|____/
                  |_|                 """,
        """
 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝  """
    ]

    print(choice(banners))

def print_easter_eggs():
    log_yellow(f"Wapiti {WAPITI_VERSION} (wapiti-scanner.github.io)")
    moon_phase = phase()
    if moon_phase == "full":
        log_blue("[*] You are lucky! Full moon tonight.")
    elif moon_phase == "new":
        log_blue("[*] Be careful! New moon tonight.")

    if datetime.now().weekday() == 4:
        if datetime.now().day == 13:
            log_blue("[*] Watch out! Bad things can happen on Friday the 13th.")
        elif datetime.now().month == 8 and datetime.now().day < 8:
            log_blue("[*] Today is International Beer Day!")

    if datetime.now().month == 5 and datetime.now().day == 4:
        log_blue("[*] May the force be with you!")
    elif datetime.now().month == datetime.now().day == 1:
        log_blue("[*] Happy new year!")
    elif datetime.now().month == 12 and datetime.now().day == 25:
        log_blue("[*] Merry christmas!")
    elif datetime.now().month == 3 and datetime.now().day == 31:
        log_blue("[*] Today is world backup day! Is your data safe?")
