#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
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
import re
from collections import defaultdict, namedtuple
from os.path import join as path_join
from typing import Optional, Iterator

from httpx import ReadTimeout, RequestError, InvalidURL

from wapitiCore.main.log import log_red, log_orange, log_verbose, logging
from wapitiCore.attack.attack import Attack, Parameter
from wapitiCore.model import PayloadInfo
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.file import PathTraversalFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.net import Request, Response

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
    name = "file"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        self.known_false_positives = defaultdict(set)
        self.mutator = self.get_mutator()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "fileHandlingPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("payload", lambda x: x.replace("[EXTERNAL_ENDPOINT]", self.external_endpoint))
        parser.add_key_handler("messages", lambda x: x.splitlines())
        parser.add_key_handler("rules", lambda x: x.splitlines())

        yield from parser

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
                # Store false positive information in order to prevent doing unnecessary requests
                self.known_false_positives[request.path_id].add(pattern)
                return True

        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):

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

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_medium(
                    request_id=request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter.display_name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
                continue
            except InvalidURL:
                logging.warning(f"Invalid URL: {mutated_request.url} potentially vulnerable to open redirect")
                continue
            else:
                file_warning = None
                for i, rule in enumerate(payload_info.rules):
                    if rule in response.content:
                        found_pattern = rule
                        vulnerable_method = payload_info.messages[i]
                        inclusion_succeed = True
                        break
                else:
                    # No successful inclusion or directory traversal, but perhaps we can control something
                    inclusion_succeed = False
                    file_warning = find_warning_message(response.content, payload_info.payload)
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
                        vulnerable_method = f"Possible {vulnerable_method} vulnerability"
                        warned = True

                    # An error message implies that a vulnerability may exist
                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vulnerable_method, page)
                    else:
                        vuln_message = f"{vulnerable_method} via injection in the parameter {parameter.display_name}"

                    constraint_message = ""
                    if file_warning and file_warning.uri:
                        constraints = has_prefix_or_suffix(payload_info.payload, file_warning.uri)
                        if constraints:
                            constraint_message += "Constraints: " + ", ".join(constraints)
                            vuln_message += " (" + constraint_message + ")"

                    await self.add_critical(
                        request_id=request.path_id,
                        finding_class=PathTraversalFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                        response=response,
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                        vulnerable_method,
                        page,
                        parameter.display_name
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

                elif response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_high(
                        request_id=request.path_id,
                        finding_class=InternalErrorFinding,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
