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
import re
from itertools import chain

from requests.exceptions import ReadTimeout, RequestException

from wapitiCore.attack.attack import Attack, Flags
from wapitiCore.language.vulnerability import Messages, MEDIUM_LEVEL, HIGH_LEVEL, CRITICAL_LEVEL, _
from wapitiCore.definitions.sql import NAME

# From https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml
DBMS_ERROR_PATTERNS = {
    "MySQL": [
        re.compile(r"SQL syntax.*?MySQL"),
        re.compile(r"Warning.*?\Wmysqli?_"),
        re.compile(r"MySQLSyntaxErrorException"),
        re.compile(r"valid MySQL result"),
        re.compile(r"check the manual that (corresponds to|fits) your MySQL server version"),
        re.compile(r"Unknown column '[^ ]+' in 'field list'"),
        re.compile(r"MySqlClient\."),
        re.compile(r"com\.mysql\.jdbc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
        re.compile(r"Pdo[./_\\]Mysql"),
        re.compile(r"MySqlException"),
        re.compile(r"SQLSTATE\[\d+\]: Syntax error or access violation")
    ],
    "MariaDB": [
        re.compile(r"check the manual that (corresponds to|fits) your MariaDB server version"),

    ],
    "Drizzle": [
        re.compile(r"check the manual that (corresponds to|fits) your Drizzle server version")
    ],
    "MemSQL": [
        re.compile(r"MemSQL does not support this type of query"),
        re.compile(r"is not supported by MemSQL"),
        re.compile(r"unsupported nested scalar subselect")
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*?ERROR"),
        re.compile(r"Warning.*?\Wpg_"),
        re.compile(r"valid PostgreSQL result"),
        re.compile(r"Npgsql\."),
        re.compile(r"PG::SyntaxError:"),
        re.compile(r"org\.postgresql\.util\.PSQLException"),
        re.compile(r"ERROR:\s\ssyntax error at or near"),
        re.compile(r"ERROR: parser: parse error at or near"),
        re.compile(r"PostgreSQL query failed"),
        re.compile(r"org\.postgresql\.jdbc"),
        re.compile(r"Pdo[./_\\]Pgsql"),
        re.compile(r"PSQLException"),
    ],
    "Microsoft SQL Server": [
        re.compile(r"Driver.*? SQL[\-\_\ ]*Server"),
        re.compile(r"OLE DB.*? SQL Server"),
        re.compile(r"\bSQL Server[^&lt;&quot;]+Driver"),
        re.compile(r"Warning.*?\W(mssql|sqlsrv)_"),
        re.compile(r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"),
        re.compile(r"System\.Data\.SqlClient\.SqlException"),
        re.compile(r"(?s)Exception.*?\bRoadhouse\.Cms\."),
        re.compile(r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}"),
        re.compile(r"\[SQL Server\]"),
        re.compile(r"ODBC SQL Server Driver"),
        re.compile(r"ODBC Driver \d+ for SQL Server"),
        re.compile(r"SQLServer JDBC Driver"),
        re.compile(r"com\.jnetdirect\.jsql"),
        re.compile(r"macromedia\.jdbc\.sqlserver"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"),
        re.compile(r"com\.microsoft\.sqlserver\.jdbc"),
        re.compile(r"Pdo[./_\\](Mssql|SqlSrv)"),
        re.compile(r"SQL(Srv|Server)Exception"),
    ],
    "Microsoft Access": [
        re.compile(r"Microsoft Access (\d+ )?Driver"),
        re.compile(r"JET Database Engine"),
        re.compile(r"Access Database Engine"),
        re.compile(r"ODBC Microsoft Access"),
        re.compile(r"Syntax error \(missing operator\) in query expression"),
    ],
    "Oracle": [
        re.compile(r"\bORA-\d{5}"),
        re.compile(r"Oracle error"),
        re.compile(r"Oracle.*?Driver"),
        re.compile(r"Warning.*?\W(oci|ora)_"),
        re.compile(r"quoted string not properly terminated"),
        re.compile(r"SQL command not properly ended"),
        re.compile(r"macromedia\.jdbc\.oracle"),
        re.compile(r"oracle\.jdbc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Oracle_Exception"),
        re.compile(r"Pdo[./_\\](Oracle|OCI)"),
        re.compile(r"OracleException"),
    ],
    "IBM DB2": [
        re.compile(r"CLI Driver.*?DB2"),
        re.compile(r"DB2 SQL error"),
        re.compile(r"\bdb2_\w+\("),
        re.compile(r"SQLCODE[=:\d, -]+SQLSTATE"),
        re.compile(r"com\.ibm\.db2\.jcc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Db2_Exception"),
        re.compile(r"Pdo[./_\\]Ibm"),
        re.compile(r"DB2Exception"),
        re.compile(r"ibm_db_dbi\.ProgrammingError"),
    ],
    "Informix": [
        re.compile(r"Warning.*?\Wifx_"),
        re.compile(r"Exception.*?Informix"),
        re.compile(r"Informix ODBC Driver"),
        re.compile(r"ODBC Informix driver"),
        re.compile(r"com\.informix\.jdbc"),
        re.compile(r"weblogic\.jdbc\.informix"),
        re.compile(r"Pdo[./_\\]Informix"),
        re.compile(r"IfxException"),
    ],
    "Firebird": [
        re.compile(r"Dynamic SQL Error"),
        re.compile(r"Warning.*?\Wibase_"),
        re.compile(r"org\.firebirdsql\.jdbc"),
        re.compile(r"Pdo[./_\\]Firebird"),

    ],
    "SQLite": [
        re.compile(r"SQLite/JDBCDriver"),
        re.compile(r"SQLite\.Exception"),
        re.compile(r"(Microsoft|System)\.Data\.SQLite\.SQLiteException"),
        re.compile(r"Warning.*?\W(sqlite_|SQLite3::)"),
        re.compile(r"\[SQLITE_ERROR\]"),
        re.compile(r"SQLite error \d+:"),
        re.compile(r"sqlite3.OperationalError:"),
        re.compile(r"SQLite3::SQLException"),
        re.compile(r"org\.sqlite\.JDBC"),
        re.compile(r"Pdo[./_\\]Sqlite"),
        re.compile(r"SQLiteException"),
    ],
    "SAP MaxDB": [
        re.compile(r"SQL error.*?POS([0-9]+)"),
        re.compile(r"Warning.*?\Wmaxdb_"),
        re.compile(r"DriverSapDB"),
        re.compile(r"-3014.*?Invalid end of SQL statement"),
        re.compile(r"com\.sap\.dbtech\.jdbc"),
        re.compile(r"\[-3008\].*?: Invalid keyword or missing delimiter"),
    ],
    "Sybase": [
        re.compile(r"Warning.*?\Wsybase_"),
        re.compile(r"Sybase message"),
        re.compile(r"Sybase.*?Server message"),
        re.compile(r"SybSQLException"),
        re.compile(r"Sybase\.Data\.AseClient"),
        re.compile(r"com\.sybase\.jdbc"),
    ],
    "Ingres": [
        re.compile(r"Warning.*?\Wingres_"),
        re.compile(r"Ingres SQLSTATE"),
        re.compile(r"Ingres\W.*?Driver"),
        re.compile(r"com\.ingres\.gcf\.jdbc"),
    ],
    "FrontBase": [
        re.compile(r"Exception (condition )?\d+\. Transaction rollback"),
        re.compile(r"com\.frontbase\.jdbc"),
        re.compile(r"Syntax error 1. Missing"),
        re.compile(r"(Semantic|Syntax) error [1-4]\d{2}\."),
    ],
    "HSQLDB": [
        re.compile(r"Unexpected end of command in statement \["),
        re.compile(r"Unexpected token.*?in statement \["),
        re.compile(r"org\.hsqldb\.jdbc"),
    ],
    "H2": [
        re.compile(r"org\.h2\.jdbc"),
        re.compile(r"\[42000-192\]"),
    ],
    "MonetDB": [
        re.compile(r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)"),
        re.compile(r"\[MonetDB\]\[ODBC Driver"),
        re.compile(r"nl\.cwi\.monetdb\.jdbc"),
    ],
    "Apache Derby": [
        re.compile(r"Syntax error: Encountered"),
        re.compile(r"org\.apache\.derby"),
        re.compile(r"ERROR 42X01"),
    ],
    "Vertica": [
        re.compile(r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):"),
        re.compile(r"/vertica/Parser/scan"),
        re.compile(r"com\.vertica\.jdbc"),
        re.compile(r"org\.jkiss\.dbeaver\.ext\.vertica"),
        re.compile(r"com\.vertica\.dsi\.dataengine"),
    ],
    "Mckoi": [
        re.compile(r"com\.mckoi\.JDBCDriver"),
        re.compile(r"com\.mckoi\.database\.jdbc"),
        re.compile(r"&lt;REGEX_LITERAL&gt;"),
    ],
    "Presto": [
        re.compile(r"com\.facebook\.presto\.jdbc"),
        re.compile(r"io\.prestosql\.jdbc"),
        re.compile(r"com\.simba\.presto\.jdbc"),
        re.compile(r"UNION query has different number of fields: \d+, \d+"),
    ],
    "Altibase": [
        re.compile(r"Altibase\.jdbc\.driver")
    ],
    "MimerSQL": [
        re.compile(r"com\.mimer\.jdbc"),
        re.compile(r"Syntax error,[^\n]+assumed to mean"),
    ],
    "CrateDB": [
        re.compile(r"io\.crate\.client\.jdbc"),
    ],
    "Cache": [
        re.compile(r"encountered after end of query"),
        re.compile(r"A comparison operator is required here"),
    ]
}


class mod_sql(Attack):
    """
    Detect SQL (but also LDAP and XPath) injection vulnerabilities by triggering errors (error-based technique).
    """

    time_to_sleep = 6
    name = "sql"
    payloads = ("[VALUE]\xBF'\"(", Flags())
    filename_payload = "'\"("  # TODO: wait for https://github.com/shazow/urllib3/pull/856 then use that for files upld

    @staticmethod
    def _find_pattern_in_response(data):
        for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
            for regex in regex_list:
                if regex.search(data):
                    return _("SQL Injection") + " (DMBS: {})".format(dbms)

        # Can't guess the DBMS but may be useful
        if "Unclosed quotation mark after the character string" in data:
            return _(".NET SQL Injection")
        if "StatementCallback; bad SQL grammar" in data:
            return _("Spring JDBC Injection")

        if "XPathException" in data:
            return _("XPath Injection")
        if "Warning: SimpleXMLElement::xpath():" in data:
            return _("XPath Injection")
        if "supplied argument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
            return _("LDAP Injection")

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
        self.time_to_sleep = str(1 + int(timeout))

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
                        self.log_orange(Messages.MSG_TIMEOUT, page)
                        self.log_orange(Messages.MSG_EVIL_REQUEST)
                        self.log_orange(mutated_request.http_repr())
                        self.log_orange("---")

                        if parameter == "QUERY_STRING":
                            anom_msg = Messages.MSG_QS_TIMEOUT
                        else:
                            anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter)

                        self.add_anom(
                            request_id=original_request.path_id,
                            category=Messages.RES_CONSUMPTION,
                            level=MEDIUM_LEVEL,
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
                                vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=NAME,
                                level=CRITICAL_LEVEL,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter
                            )

                            self.log_red("---")
                            self.log_red(
                                Messages.MSG_QS_INJECT if parameter == "QUERY_STRING" else Messages.MSG_PARAM_INJECT,
                                vuln_info,
                                page,
                                parameter
                            )
                            self.log_red(Messages.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")

                            # We reached maximum exploitation for this parameter, don't send more payloads
                            vulnerable_parameter = True
                            continue

                        elif response.status == 500 and not saw_internal_error:
                            saw_internal_error = True
                            if parameter == "QUERY_STRING":
                                anom_msg = Messages.MSG_QS_500
                            else:
                                anom_msg = Messages.MSG_PARAM_500.format(parameter)

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Messages.ERROR_500,
                                level=HIGH_LEVEL,
                                request=mutated_request,
                                info=anom_msg,
                                parameter=parameter
                            )

                            self.log_orange("---")
                            self.log_orange(Messages.MSG_500, page)
                            self.log_orange(Messages.MSG_EVIL_REQUEST)
                            self.log_orange(mutated_request.http_repr())
                            self.log_orange("---")
                except (KeyboardInterrupt, RequestException) as exception:
                    yield exception

            yield original_request
