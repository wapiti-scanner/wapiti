#!/usr/bin/env python3
# Took this from https://github.com/tdhopper/moon/blob/master/moon.py
from datetime import datetime


# Adapted the moon phase code from
# http://smithje.github.io/bash/2013/07/08/moon-phase-prompt.html

MOON_PHASES = [
    (1.84566, "new"),
    (5.53699, "waxing crescent"),
    (9.22831, "first quarter"),
    (12.91963, "waxing gibbous"),
    (16.61096, "full"),
    (20.30228, "waning gibbous"),
    (23.99361, "last quarter"),
    (27.68493, "waning crescent")
]


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

    for value, name in MOON_PHASES:
        if moon_phase < value:
            return name

    return "new"


if __name__ == "__main__":
    print(phase())
