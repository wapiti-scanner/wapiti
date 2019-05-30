#!/usr/bin/env python3
# Took this from https://github.com/tdhopper/moon/blob/master/moon.py
from datetime import datetime


# Adapted the moon phase code from
# http://smithje.github.io/bash/2013/07/08/moon-phase-prompt.html

def julian(year, month, day) -> float:
    a = (14 - month) / 12.0
    y = year + 4800 - a
    m = (12 * a) - 3 + month
    return day + (153 * m + 2) / 5.0 + (365 * y) + y / 4.0 - y / 100.0 + y / 400.0 - 32045


def phase(year=None, month=None, day=None) -> str:
    if year is None and month is None and day is None:
        today = datetime.now()
        year, month, day = today.year, today.month, today.day
    p = (julian(year, month, day) - julian(2000, 1, 6)) % 29.530588853

    if p < 1.84566:
        return "new"
    elif p < 5.53699:
        return "waxing crescent"
    elif p < 9.22831:
        return "first quarter"
    elif p < 12.91963:
        return "waxing gibbous"
    elif p < 16.61096:
        return "full"
    elif p < 20.30228:
        return "waning gibbous"
    elif p < 23.99361:
        return "last quarter"
    elif p < 27.68493:
        return "waning crescent"
    else:
        return "new"


if __name__ == "__main__":
    print(phase())
