#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2008-2021 Nicolas Surribas
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
from configparser import ConfigParser
from os.path import join as path_join
from collections import defaultdict, namedtuple
import re

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, PayloadReader
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.file import NAME
from wapitiCore.net.web import Request


PHP_WARNING_REGEXES = [
    # Most useful regex must be at top
    re.compile(
        r"(?:<b>)?Warning(?:</b>)?:\s+(?P<function>\w+)\(\).*"
        r"Failed opening '(?P<uri>.+)' (?:for inclusion)?.*in (?:<b>)?(?P<path>[^<>]*)(?:</b>)? "
        r"on line (?:<\w+>)?(\d*)(?:</\w+>)?"
    ),
    re.compile(
        r"(?:<b>)?Warning(?:</b>)?:\s+(?P<function>\w+)\((?P<uri>.+)\).*"
        r"failed to open stream:.*in (?:<b>)?(?P<path>[^<>]*)(?:</b>)? "
        r"on line (?:<\w+>)?(\d*)(?:</\w+>)?"
    )
]


FileWarning = namedtuple('FileWarning', ['pattern', 'function', 'uri', 'path'])
PHP_FUNCTIONS = (
    "fread", "fpassthru", "include", "require", "file", "readfile", "file_get_contents", "show_source",
    "highlight_file", "include_once", "require_once"
)

# The following table contains tuples of (pattern, description)
# Most important patterns must appear at the top of this table.
WARNING_DESC = [
    # Warnings
    ("java.io.FileNotFoundException:", "Java include/open"),
    ("System.IO.FileNotFoundException:", ".NET File.Open*"),
    ("error '800a0046'", "VBScript OpenTextFile")
]


def has_prefix_or_suffix(pattern, string):
    """Return whether a pattern is present in a string with or without a prefix and/or suffix."""
    results = []
    if pattern not in string:
        return results

    if not string.startswith(pattern):
        results.append("prefix")
    if not string.endswith(pattern):
        results.append("suffix")
    return sorted(results)


def find_warning_message(data, payload):
    """This method searches patterns in the response from the server"""
    for warning_regex in PHP_WARNING_REGEXES:
        for match in warning_regex.finditer(data):
            items = match.groupdict()
            if payload not in items["uri"]:
                # False positive: the page is raising a warning for something we do not injected
                continue

            return FileWarning(
                pattern=match.group(),
                function=items["function"] + "()",
                uri=items["uri"],
                path=items["path"]
            )

    for pattern, description in WARNING_DESC:
        if pattern in data:
            return FileWarning(pattern=pattern, function=description, uri="", path="")

    return None


class ModuleFile(Attack):
    """Detect file-related vulnerabilities such as directory traversal and include() vulnerabilities."""

    PAYLOADS_FILE = "fileHandlingPayloads.ini"

    name = "file"

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        self.rules_to_messages = {}
        self.payload_to_rules = {}
        self.known_false_positives = defaultdict(set)
        self.mutator = self.get_mutator()

    @property
    def payloads(self):
        """Load the payloads from the specified file"""
        if not self.PAYLOADS_FILE:
            return []

        payloads = []

        config_reader = ConfigParser(interpolation=None)
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE), encoding='utf-8') as payload_file:
            config_reader.read_file(payload_file)

        # No time based payloads here so we don't care yet
        reader = PayloadReader(self.options)

        for section in config_reader.sections():
            clean_payload, original_flags = reader.process_line(config_reader[section]["payload"])
            flags = original_flags.with_section(section)

            rules = config_reader[section]["rules"].splitlines()
            messages = [_(message) for message in config_reader[section]["messages"].splitlines()]
            self.payload_to_rules[section] = rules
            self.rules_to_messages.update(dict(zip(rules, messages)))

            payloads.append((clean_payload, flags))

        return payloads

    async def is_false_positive(self, request, pattern):
        """Check if the response for a given request contains an expected pattern."""
        if not pattern:
            # Should not happen
            return False

        if pattern in self.known_false_positives[request.path_id]:
            return True

        try:
            response = await self.crawler.async_send(request)
        except RequestError:
            self.network_errors += 1
            # Can't check out, avoid false negative
            return False
        else:
            if pattern in response.content:
                # Store false positive informations in order to prevent doing unnecessary requests
                self.known_false_positives[request.path_id].add(pattern)
                return True

        return False

    async def attack(self, request: Request):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload, flags in self.mutator.mutate(request):
            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                if parameter == "QUERY_STRING":
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter)

                await self.add_anom_medium(
                    request_id=request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
                continue
            else:
                file_warning = None
                # original_payload = self.payload_to_rules[flags.section]
                for rule in self.payload_to_rules[flags.section]:
                    if rule in response.content:
                        found_pattern = rule
                        vulnerable_method = self.rules_to_messages[rule]
                        inclusion_succeed = True
                        break
                else:
                    # No successful inclusion or directory traversal but perhaps we can control something
                    inclusion_succeed = False
                    file_warning = find_warning_message(response.content, payload)
                    if file_warning:
                        found_pattern = file_warning.pattern
                        vulnerable_method = file_warning.function
                    else:
                        found_pattern = vulnerable_method = None

                if found_pattern:
                    # Interesting pattern found, either inclusion or error message
                    if await self.is_false_positive(request, found_pattern):
                        continue

                    if not inclusion_succeed:
                        if warned:
                            # No need to warn more than once
                            continue

                        # Mark as eventuality
                        vulnerable_method = _("Possible {0} vulnerability").format(vulnerable_method)
                        warned = True

                    # An error message implies that a vulnerability may exists
                    if parameter == "QUERY_STRING":
                        vuln_message = Messages.MSG_QS_INJECT.format(vulnerable_method, page)
                    else:
                        vuln_message = _("{0} via injection in the parameter {1}").format(
                            vulnerable_method, parameter
                        )

                    constraint_message = ""
                    if file_warning and file_warning.uri:
                        constraints = has_prefix_or_suffix(payload, file_warning.uri)
                        if constraints:
                            constraint_message += _("Constraints: {}").format(", ".join(constraints))
                            vuln_message += " (" + constraint_message + ")"

                    await self.add_vuln_critical(
                        request_id=request.path_id,
                        category=NAME,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_QS_INJECT if parameter == "QUERY_STRING" else Messages.MSG_PARAM_INJECT,
                        vulnerable_method,
                        page,
                        parameter
                    )

                    if constraint_message:
                        log_red(constraint_message)

                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")

                    if inclusion_succeed:
                        # We reached maximum exploitation for this parameter, don't send more payloads
                        vulnerable_parameter = True
                        continue

                elif response.status == 500 and not saw_internal_error:
                    saw_internal_error = True
                    if parameter == "QUERY_STRING":
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter)

                    await self.add_anom_high(
                        request_id=request.path_id,
                        category=Messages.ERROR_500,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
