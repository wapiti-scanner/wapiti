#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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
from itertools import chain
from configparser import ConfigParser
from os.path import join as path_join
from collections import defaultdict

from requests.exceptions import ReadTimeout, RequestException

from wapitiCore.attack.attack import Attack, PayloadReader
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_file(Attack):
    """This class implements a file handling attack"""

    PAYLOADS_FILE = "fileHandlingPayloads.ini"

    name = "file"

    # The following table contains tuples of (pattern, description, severity)
    # a severity of 1 is a file disclosure (inclusion, read etc) vulnerability
    # a severity of 0 is just the detection of an error returned by the server
    # Most important patterns must appear at the top of this table.
    warnings_desc = [
        # Warnings
        ("java.io.FileNotFoundException:", "Java include/open"),
        ("fread(): supplied argument is not", "fread()"),
        ("fpassthru(): supplied argument is not", "fpassthru()"),
        ("for inclusion (include_path=", "include()"),
        ("Failed opening required", "require()"),
        ("Warning: file(", "file()"),
        ("<b>Warning</b>:  file(", "file()"),
        ("Warning: readfile(", "readfile()"),
        ("<b>Warning:</b>  readfile(", "readfile()"),
        ("Warning: file_get_contents(", "file_get_contents()"),
        ("<b>Warning</b>:  file_get_contents(", "file_get_contents()"),
        ("Warning: show_source(", "show_source()"),
        ("<b>Warning:</b>  show_source(", "show_source()"),
        ("Warning: highlight_file(", "highlight_file()"),
        ("<b>Warning:</b>  highlight_file(", "highlight_file()"),
        ("System.IO.FileNotFoundException:", ".NET File.Open*"),
        ("error '800a0046'", "VBScript OpenTextFile")
    ]

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.rules_to_messages = {}
        self.payload_to_rules = {}
        self.known_false_positives = defaultdict(set)

    @property
    def payloads(self):
        """Load the payloads from the specified file"""
        if not self.PAYLOADS_FILE:
            return []

        payloads = []

        config_reader = ConfigParser(interpolation=None)
        config_reader.read_file(open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE)))
        # No time based payloads here so we don't care yet
        reader = PayloadReader(self.options)

        for section in config_reader.sections():
            clean_payload, flags = reader.process_line(config_reader[section]["payload"])
            flags.add(section)

            rules = config_reader[section]["rules"].splitlines()
            messages = [_(message) for message in config_reader[section]["messages"].splitlines()]
            self.payload_to_rules[section] = rules
            self.rules_to_messages.update(dict(zip(rules, messages)))

            payloads.append((clean_payload, flags))

        return payloads

    def _find_warning_message(self, data):
        """This method searches patterns in the response from the server"""
        for pattern, description in self.warnings_desc:
            if pattern in data:
                return pattern, description

        return None, None

    def is_false_positive(self, request, pattern):
        """Check if the response for a given request contains an expected pattern."""
        if not pattern:
            # Should not happen
            return False

        if pattern in self.known_false_positives[request.path_id]:
            return True

        try:
            response = self.crawler.send(request)
        except RequestException:
            # Can't check out, avoid false negative
            return False
        else:
            if pattern in response.content:
                # Store false positive informations in order to prevent doing unnecessary requests
                self.known_false_positives[request.path_id].add(pattern)
                return True

        return False

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            warned = False
            timeouted = False
            page = original_request.path
            saw_internal_error = False
            current_parameter = None
            vulnerable_parameter = False

            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, payload, flags in mutator.mutate(original_request):
                try:
                    if current_parameter != parameter:
                        # Forget what we know about current parameter
                        current_parameter = parameter
                        vulnerable_parameter = False
                    elif vulnerable_parameter:
                        # If parameter is vulnerable, just skip till next parameter
                        continue

                    if self.verbose == 2:
                        print("[¨] {0}".format(mutated_request))

                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        if timeouted:
                            continue

                        self.log_orange("---")
                        self.log_orange(Anomaly.MSG_TIMEOUT, page)
                        self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                        self.log_orange(mutated_request.http_repr())
                        self.log_orange("---")

                        if parameter == "QUERY_STRING":
                            anom_msg = Anomaly.MSG_QS_TIMEOUT
                        else:
                            anom_msg = Anomaly.MSG_PARAM_TIMEOUT.format(parameter)

                        self.add_anom(
                            request_id=original_request.path_id,
                            category=Anomaly.RES_CONSUMPTION,
                            level=Anomaly.MEDIUM_LEVEL,
                            request=mutated_request,
                            info=anom_msg,
                            parameter=parameter
                        )
                        timeouted = True
                    else:
                        original_payload = [flag for flag in flags if flag in self.payload_to_rules][0]
                        for rule in self.payload_to_rules[original_payload]:
                            if rule in response.content:
                                found_pattern = rule
                                vuln_info = self.rules_to_messages[rule]
                                inclusion_succeed = True
                                break
                        else:
                            found_pattern, vuln_info = self._find_warning_message(response.content)
                            inclusion_succeed = False

                        if found_pattern:
                            # Interesting pattern found, either inclusion or error message
                            if self.is_false_positive(original_request, found_pattern):
                                continue

                            if not inclusion_succeed:
                                if warned:
                                    # No need to warn more than once
                                    continue

                                # Mark as eventuality
                                vuln_info = _("Possible {0} vulnerability").format(vuln_info)
                                warned = True

                            # An error message implies that a vulnerability may exists
                            if parameter == "QUERY_STRING":
                                vuln_message = Vulnerability.MSG_QS_INJECT.format(vuln_info, page)
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.FILE_HANDLING,
                                level=Vulnerability.HIGH_LEVEL,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter
                            )

                            self.log_red("---")
                            self.log_red(
                                Vulnerability.MSG_QS_INJECT if parameter == "QUERY_STRING" else Vulnerability.MSG_PARAM_INJECT,
                                vuln_info,
                                page,
                                parameter
                            )
                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")

                            if inclusion_succeed:
                                # We reached maximum exploitation for this parameter, don't send more payloads
                                vulnerable_parameter = True
                                continue

                        elif response.status == 500 and not saw_internal_error:
                            saw_internal_error = True
                            if parameter == "QUERY_STRING":
                                anom_msg = Anomaly.MSG_QS_500
                            else:
                                anom_msg = Anomaly.MSG_PARAM_500.format(parameter)

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Anomaly.ERROR_500,
                                level=Anomaly.HIGH_LEVEL,
                                request=mutated_request,
                                info=anom_msg,
                                parameter=parameter
                            )

                            self.log_orange("---")
                            self.log_orange(Anomaly.MSG_500, page)
                            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                            self.log_orange(mutated_request.http_repr())
                            self.log_orange("---")
                except (KeyboardInterrupt, RequestException) as exception:
                    yield exception

            yield original_request
