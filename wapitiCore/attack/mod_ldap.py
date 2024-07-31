#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2024 Nicolas Surribas
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
import dataclasses
import html
from collections import defaultdict
from os.path import join as path_join
from typing import Optional, Iterator, List, Tuple, Dict, Any
from hashlib import md5
from urllib.parse import quote_plus, quote

from httpx import RequestError

from wapitiCore.main.log import log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.ldapi import LdapInjectionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.net import Request, Response
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


@dataclasses.dataclass
class PayloadInfo:
    payload: str
    context: str
    status: bool


def string_without_payload(text: str, payload: str) -> str:
    # Most search pages will show your search term. This will make the hash of the page change each time
    # We remove here the search term its possible HTML escaped version.
    return text.replace(
        payload, ""
    ).replace(
        html.escape(payload), ""
    ).replace(
        quote_plus(payload), ""
    ).replace(
        quote(payload), "",
    )


# from https://github.com/andresriancho/w3af/blob/master/w3af/plugins/audit/ldapi.py
LDAP_ERRORS = (
    # Not sure which lang or LDAP engine
    'supplied argument is not a valid ldap',

    # Java
    'javax.naming.NameNotFoundException',
    'LDAPException',
    'com.sun.jndi.ldap',

    # PHP
    'Bad search filter',

    # http://support.microsoft.com/kb/218185
    'Protocol error occurred',
    'Size limit has exceeded',
    'An inappropriate matching occurred',
    'A constraint violation occurred',
    'The syntax is invalid',
    'Object does not exist',
    'The alias is invalid',
    'The distinguished name has an invalid syntax',
    'The server does not handle directory requests',
    'There was a naming violation',
    'There was an object class violation',
    'Results returned are too large',
    'Unknown error occurred',
    'Local error occurred',
    'The search filter is incorrect',
    'The search filter is invalid',
    'The search filter cannot be recognized',

    # OpenLDAP
    'Invalid DN syntax',
    'No Such Object',

    # IPWorks LDAP
    # http://www.tisc-insight.com/newsletters/58.html
    'IPWorksASP.LDAP',

    # https://entrack.enfoldsystems.com/browse/SERVERPUB-350
    'Module Products.LDAPMultiPlugins'
)


def find_ldap_error(text: str) -> Optional[str]:
    for error_message in LDAP_ERRORS:
        if error_message in text:
            return error_message
    return None


def group_mutations_per_context(mutations: List[Tuple[Request, PayloadInfo]]) -> Dict[str, List[Any]]:
    mutations_per_context = defaultdict(list)
    for mutated_request, payload_info in mutations:
        mutations_per_context[payload_info.context].append((mutated_request, payload_info))
    return mutations_per_context


class ModuleLdap(Attack):
    """
    Detect scripts vulnerable to LDAP injection.
    """
    name = "ldap"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.mutator = self.get_mutator()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "ldap.ini"))
        parser.add_key_handler("payload", replace_tags)
        yield from parser

    async def is_page_dynamic(self, request: Request, payload_info: PayloadInfo, previous_md5: str) -> bool:
        """Compare the MD5 hash of an HTTP response to the one obtained earlier."""
        try:
            response = await self.crawler.async_send(request)
        except RequestError:
            self.network_errors += 1
        else:
            page_md5 = md5(
                string_without_payload(response.content, payload_info.payload).encode(errors="ignore")
            ).hexdigest()
            return page_md5 != previous_md5

        # Do you feel lucky, punk?
        return False

    async def attack_parameter(
            self,
            parameter: Parameter,
            original_request: Request,
            mutations: List[Tuple[Request, PayloadInfo]]
    ) -> bool:
        if not mutations:
            return False

        no_results_md5 = None
        error_md5 = None

        vuln_request = None
        vuln_response = None
        warn_request = None
        warn_response = None
        http500_request = None
        http500_response = None

        # We group mutated requests per their related payload context.
        # We do so because we must forget about all previous tests for each context.
        for _, tuples in group_mutations_per_context(mutations).items():
            tests = []

            for mutated_request, payload_info in tuples:
                if payload_info.context not in ("no_results", "error"):
                    log_verbose(f"[¨] {mutated_request}")

                try:
                    response = await self.crawler.async_send(mutated_request)
                except RequestError:
                    self.network_errors += 1
                else:
                    page_md5 = md5(
                        string_without_payload(response.content, payload_info.payload).encode(errors="ignore")
                    ).hexdigest()

                    if payload_info.context == "no_results":
                        if not await self.is_page_dynamic(mutated_request, payload_info, page_md5):
                            # Hash used for responses with no results
                            no_results_md5 = page_md5
                    elif payload_info.context == "error":
                        # Hash used for responses bumping into an invalid (bad syntax) LDAP query
                        error_md5 = page_md5
                    elif no_results_md5 and error_md5:
                        if payload_info.status is True:
                            # Our payload is trying to get all entries. The md5 should be different from
                            # the "no results" response and different from the LDAP error response.
                            current_test = page_md5 not in (no_results_md5, error_md5)
                            if vuln_request is None:
                                vuln_request = mutated_request
                                vuln_response = response
                        else:
                            # Our payload is trying to pass a valid LDAP query that would return no results.
                            # It should therefore be equal to no_results_md5.
                            # It may also be equal to error_md5 because some webpage will hide the error and pretend no
                            # results are available
                            current_test = page_md5 in (no_results_md5, error_md5)

                        tests.append(current_test)

                        if not current_test:
                            if find_ldap_error(response.content) and warn_request is None:
                                warn_request = mutated_request
                                warn_response = response
                            elif response.status == 500 and http500_request is None:
                                http500_request = mutated_request
                                http500_response = response

            # If we found a vulnerability thanks to our tests then warn the user
            if len(tests) >= 2 and all(tests):
                if parameter.is_qs_injection:
                    vuln_message = Messages.MSG_QS_INJECT.format(LdapInjectionFinding.name(), original_request.path)
                else:
                    vuln_message = (
                        f"{LdapInjectionFinding.name()} via injection in the parameter "
                        f"{parameter.display_name}"
                    )

                await self.add_critical(
                    request_id=original_request.path_id,
                    finding_class=LdapInjectionFinding,
                    request=vuln_request,
                    info=vuln_message,
                    parameter=parameter.display_name,
                    response=vuln_response
                )

                log_red("---")
                log_red(
                    Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                    LdapInjectionFinding.name(),
                    original_request.path,
                    parameter.display_name
                )
                log_red(Messages.MSG_EVIL_REQUEST)
                log_red(vuln_request.http_repr())
                log_red("---")

                # LDAP injection succeed for the current context, it is unlikely it will work for another, stop here
                return True

        # None of the injection context worked but let's warn if we saw something shady.
        # Don't flood: 1 warning per parameter
        if warn_request:
            vuln_info = "Potential LDAP injection"
            if parameter.is_qs_injection:
                vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, original_request.path)
            else:
                vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"

            await self.add_high(
                request_id=original_request.path_id,
                finding_class=LdapInjectionFinding,
                request=warn_request,
                info=vuln_message,
                parameter=parameter.display_name,
                response=warn_response
            )

            log_red("---")
            log_red(
                Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                vuln_info,
                original_request.path,
                parameter.display_name
            )
            log_red(Messages.MSG_EVIL_REQUEST)
            log_red(warn_request.http_repr())
            log_red("---")
        elif http500_request:
            if parameter.is_qs_injection:
                anom_msg = Messages.MSG_QS_500
            else:
                anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

            await self.add_high(
                request_id=original_request.path_id,
                finding_class=InternalErrorFinding,
                request=http500_request,
                info=anom_msg,
                parameter=parameter.display_name,
                response=http500_response
            )

            log_orange("---")
            log_orange(Messages.MSG_500, original_request.path)
            log_orange(Messages.MSG_EVIL_REQUEST)
            log_orange(http500_request.http_repr())
            log_orange("---")

        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        current_parameter = None
        mutated_requests: List[Tuple[Request, PayloadInfo]] = []

        # We want to perform several tests for each parameter and once done we check all tests to validate
        # the vulnerability. It is hard to perform that with the mutator loop as we can't know  if the next iteration
        # concerns the same parameter or not.
        # Therefore, we accumulate batches of mutated requests for each parameter and another function will do the tests
        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):
            if parameter != current_parameter:
                await self.attack_parameter(current_parameter, request, mutated_requests)
                current_parameter = parameter
                mutated_requests = []

            mutated_requests.append((mutated_request, payload_info))

        await self.attack_parameter(current_parameter, request, mutated_requests)
