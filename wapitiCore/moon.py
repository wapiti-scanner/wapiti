#!/usr/bin/env python3
# Took this from https://github.com/tdhopper/moon/blob/master/moon.py
from datetime import datetime


# Adapted the moon phase code from
# http://smithje.github.io/bash/2013/07/08/moon-phase-prompt.html

def julian(year, month, day) -> float:
    year_fraction = (14 - month) / 12.0
    j_year = year + 4800 - year_fraction
    j_month = (12 * year_fraction) - 3 + month
    return day + (153 * j_month + 2) / 5.0 + (365 * j_year) + j_year / 4.0 - j_year / 100.0 + j_year / 400.0 - 32045


def phase(year=None, month=None, day=None) -> str:
    if year is None and month is None and day is None:
        today = datetime.now()
        year, month, day = today.year, today.month, today.day
    moon_phase = (julian(year, month, day) - julian(2000, 1, 6)) % 29.530588853

    if moon_phase < 1.84566:
        return "new"
    elif moon_phase < 5.53699:
        return "waxing crescent"
    elif moon_phase < 9.22831:
        return "first quarter"
    elif moon_phase < 12.91963:
        return "waxing gibbous"
    elif moon_phase < 16.61096:
        return "full"
    elif moon_phase < 20.30228:
        return "waning gibbous"
    elif moon_phase < 23.99361:
        return "last quarter"
    elif moon_phase < 27.68493:
        return "waning crescent"
    else:
        return "new"


if __name__ == "__main__":
    print(phase())
