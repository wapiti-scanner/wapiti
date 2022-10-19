from datetime import datetime
from random import choice

from wapitiCore import WAPITI_VERSION
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
    print(f"Wapiti {WAPITI_VERSION} (wapiti-scanner.github.io)")
    moon_phase = phase()
    if moon_phase == "full":
        print("[*] You are lucky! Full moon tonight.")
    elif moon_phase == "new":
        print("[*] Be careful! New moon tonight.")

    if datetime.now().weekday() == 4:
        if datetime.now().day == 13:
            print("[*] Watch out! Bad things can happen on Friday the 13th.")
        elif datetime.now().month == 8 and datetime.now().day < 8:
            print("[*] Today is International Beer Day!")

    if datetime.now().month == 5 and datetime.now().day == 4:
        print("[*] May the force be with you!")
    elif datetime.now().month == datetime.now().day == 1:
        print("[*] Happy new year!")
    elif datetime.now().month == 12 and datetime.now().day == 25:
        print("[*] Merry christmas!")
    elif datetime.now().month == 3 and datetime.now().day == 31:
        print("[*] Today is world backup day! Is your data safe?")
