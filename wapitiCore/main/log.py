#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging as std_logging
import sys

# --- Custom Log Levels ---
VERBOSE_LEVEL = 15
std_logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")


# Mapping from color names to ANSI codes
COLORS = {
    "BLUE": "\033[38;5;33m",
    "GREEN": "\033[38;5;34m",
    "ORANGE": "\033[38;5;202m",
    "YELLOW": "\033[38;5;226m",
    "RED": "\033[38;5;196m",      # Bright red for critical findings
    "ERROR_RED": "\033[48;5;196m",
    "CRITICAL_RED": "\033[48;5;196m",
    "ENDC": "\033[0m",
}


class ColoredFormatter(std_logging.Formatter):
    """
    Custom formatter to add colors to logs.
    """

    def __init__(self, fmt=None, datefmt=None, style='%', colorize=False):
        super().__init__(fmt, datefmt, style)
        self.colorize = colorize

    def format(self, record):
        message = super().format(record)
        if not self.colorize:
            return message

        # Priority 1: Use the color specified in the log call `extra`
        color_name = getattr(record, 'color_name', None)
        if color_name and color_name in COLORS:
            return COLORS[color_name] + message + COLORS["ENDC"]

        # Priority 2: Fall back to the color based on the log level
        level_color_map = {
            std_logging.INFO: COLORS["GREEN"],
            std_logging.WARNING: COLORS["ORANGE"],
            std_logging.ERROR: COLORS["ERROR_RED"],
            std_logging.CRITICAL: COLORS["CRITICAL_RED"],
        }
        color = level_color_map.get(record.levelno)
        if color:
            return color + message + COLORS["ENDC"]

        return message


# The main logger to be used across the application
logging = std_logging.getLogger("wapiti")


def configure(handlers):
    """
    Configures the root logger based on a list of handlers.
    """
    logging.handlers = []
    logging.setLevel(std_logging.DEBUG)

    level_map = {
        "DEBUG": std_logging.DEBUG,
        "INFO": std_logging.INFO,
        "VERBOSE": VERBOSE_LEVEL,
        "SUCCESS": std_logging.INFO,
        "WARNING": std_logging.WARNING,
        "ERROR": std_logging.ERROR,
        "CRITICAL": std_logging.CRITICAL,
        "BLUE": std_logging.INFO,
    }

    for handler_conf in handlers:
        sink = handler_conf.get("sink")
        level_str = handler_conf.get("level", "INFO")
        level = level_map.get(level_str, std_logging.INFO)

        handler = None
        if sink in (sys.stdout, sys.stderr):
            handler = std_logging.StreamHandler(sink)
        elif isinstance(sink, str):
            handler = std_logging.FileHandler(sink)

        if handler:
            colorize = handler_conf.get("colorize", False) and sink in (sys.stdout, sys.stderr)
            # Use a basic formatter for file logs, and our custom one for console
            if isinstance(handler, std_logging.FileHandler):
                formatter = std_logging.Formatter("{message}", style='{')
            else:
                formatter = ColoredFormatter("{message}", style='{', colorize=colorize)
            handler.setFormatter(formatter)
            handler.setLevel(level)
            logging.addHandler(handler)


def log_blue(message, *args, **kwargs):
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.info(message, extra={'color_name': 'BLUE'})


def log_green(message, *args, **kwargs):
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.info(message, extra={'color_name': 'GREEN'})


def log_red(message, *args, **kwargs):
    """Logs a critical finding (INFO level, RED color)."""
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.info(message, extra={'color_name': 'RED'})


def log_bold(message, *args, **kwargs):
    """Logs a critical error message (CRITICAL level)."""
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.critical(message)


def log_orange(message, *args, **kwargs):
    """Logs a medium finding (INFO level, ORANGE color)."""
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.info(message, extra={'color_name': 'ORANGE'})


def log_yellow(message, *args, **kwargs):
    """Logs a low-finding (INFO level, YELLOW color)."""
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.info(message, extra={'color_name': 'YELLOW'})


def log_verbose(message, *args, **kwargs):
    """Logs a message with the custom VERBOSE level."""
    if args or kwargs:
        message = message.format(*args, **kwargs)
    logging.log(VERBOSE_LEVEL, message)


def log_severity(severity, message):
    # This function doesn't use formatting, so it remains unchanged
    if severity == 1:
        log_red(message)
    elif severity == 2:
        log_orange(message)
    elif severity == 3:
        log_green(message)
    else:
        log_verbose(message)


# Default configuration
configure(handlers=[{
    "sink": sys.stdout,
    "colorize": False,
    "format": "{message}",
    "level": "INFO"
}])
