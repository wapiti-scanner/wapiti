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
import re
from itertools import chain

from requests.exceptions import ReadTimeout, RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_sql(Attack):
    """
    This class implements an error-based SQL Injection attack
    """

    TIME_TO_SLEEP = 6
    name = "sql"
    payloads = ("\xBF'\"(", set())
    filename_payload = "'\"("  # TODO: wait for https://github.com/shazow/urllib3/pull/856 then use that for files upld

    @staticmethod
    def _find_pattern_in_response(data):
        if "You have an error in your SQL syntax" in data:
            return _("MySQL Injection")
        if "supplied argument is not a valid MySQL" in data:
            return _("MySQL Injection")
        if "Warning: mysql_fetch_array()" in data:
            return _("MySQL Injection")
        if "mysqli_fetch_assoc() expects parameter 1 to be" in data:
            return _("MySQL Injection")
        if "com.mysql.jdbc.exceptions" in data:
            return _("MySQL Injection")
        if "MySqlException (0x" in data:
            return _("MySQL Injection")
        if ("[Microsoft][ODBC Microsoft Access Driver]" in data or
                "Syntax error in string in query expression " in data):
            return _("MSAccess-Based SQL Injection")
        if "[Microsoft][ODBC SQL Server Driver]" in data:
            return _("MSSQL-Based Injection")
        if 'Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error' in data:
            return _("MSSQL-Based Injection")
        if "Microsoft OLE DB Provider for ODBC Drivers" in data:
            return _("MSSQL-Based Injection")
        if "java.sql.SQLException: Syntax error or access violation" in data:
            return _("Java.SQL Injection")
        if "java.sql.SQLException: Unexpected end of command" in data:
            return _("Java.SQL Injection")
        if "PostgreSQL query failed: ERROR: parser:" in data:
            return _("PostgreSQL Injection")
        if "Warning: pg_query()" in data:
            return _("PostgreSQL Injection")
        if "XPathException" in data:
            return _("XPath Injection")
        if "Warning: SimpleXMLElement::xpath():" in data:
            return _("XPath Injection")
        if "supplied argument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
            return _("LDAP Injection")
        if "DB2 SQL error:" in data:
            return _("DB2 Injection")
        if "Dynamic SQL Error" in data:
            return _("Interbase Injection")
        if "Sybase message:" in data:
            return _("Sybase Injection")
        if "Unclosed quotation mark after the character string" in data:
            return _(".NET SQL Injection")
        if "error '80040e14'" in data and "Incorrect syntax near" in data:
            return _("MSSQL-Based Injection")
        if "StatementCallback; bad SQL grammar" in data:
            return _("Spring JDBC Injection")

        ora_test = re.search(r"ORA-[0-9]{4,}", data)
        if ora_test is not None:
            return _("Oracle Injection") + " " + ora_test.group(0)

        return ""

    def is_false_positive(self, request):
        try:
            response = self.crawler.send(request)
        except RequestException:
            pass
        else:
            if self._find_pattern_in_response(response.content):
                return True
        return False

    def set_timeout(self, timeout):
        self.TIME_TO_SLEEP = str(1 + int(timeout))

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            timeouted = False
            page = original_request.path
            saw_internal_error = False
            current_parameter = None
            vulnerable_parameter = False

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
                        vuln_info = self._find_pattern_in_response(response.content)
                        if vuln_info and not self.is_false_positive(original_request):
                            # An error message implies that a vulnerability may exists

                            if parameter == "QUERY_STRING":
                                vuln_message = Vulnerability.MSG_QS_INJECT.format(vuln_info, page)
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.SQL_INJECTION,
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
