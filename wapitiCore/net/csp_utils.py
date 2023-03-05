# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
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

from wapitiCore.parsers.html_parser import Html
from wapitiCore.net.response import Response


POLICY_REGEX = re.compile(r"\s*((?:'[^']*')|(?:[^'\s]+))\s*")

CSP_CHECK_LISTS = {
    # As default-src is the fallback directive we may want to avoid those duplicates in the future
    "default-src": ["unsafe-inline", "data:", "http:", "https:", "*", "unsafe-eval"],
    "script-src": ["unsafe-inline", "data:", "http:", "https:", "*", "unsafe-eval"],
    "object-src": ["none"],
    "base-uri": ["none", "self"]
}

CSP_HEADERS = {"content-security-policy", "x-content-security-policy", "x-webkit-csp"}


def has_csp_header(response: Response):
    headers = {header.lower() for header in response.headers}
    if CSP_HEADERS & headers:
        return True

    return False


def has_csp_meta(page: Html):
    for meta_http in page.soup.find_all("meta", attrs={"http-equiv": True}):
        if meta_http["http-equiv"].lower().strip() in CSP_HEADERS:
            return True

    return False


def get_csp_header(response: Response) -> str:
    for header in CSP_HEADERS:
        if header in response.headers:
            return response.headers[header]
    return ""


def get_csp_meta(page: Html) -> str:
    for meta_http in page.soup.find_all("meta", attrs={"http-equiv": True, "content": True}):
        for header in CSP_HEADERS:
            if meta_http["http-equiv"].lower().strip() == header:
                return meta_http["content"]

    return ""


def get_csp(response):
    for header in CSP_HEADERS:
        if header in response.headers:
            return response.headers[header]

    for meta_http in response.soup.find_all("meta", attrs={"http-equiv": True, "content": True}):
        for header in CSP_HEADERS:
            if meta_http["http-equiv"].lower().strip() == header:
                return meta_http["content"]

    return ""


def csp_header_to_dict(header):
    csp_dict = {}

    for policy_string in header.split(";"):
        try:
            policy_name, policy_values = policy_string.strip().split(" ", 1)
        except ValueError:
            # Either it is malformed or we reach the end
            continue
        csp_dict[policy_name] = [value.strip("'") for value in POLICY_REGEX.findall(policy_values)]

    return csp_dict


def check_policy_values(policy_name, csp_dict):
    """
    This function return the status of the tested element in the CSP as an int. Possible values:
    -1 : the element is missing in the CSP
    0  : the element is set, but his value is not secure
    1  : the element is set and his value is secure
    """

    if policy_name not in csp_dict and "default-src" not in csp_dict:
        return -1

    # The HTTP CSP "default-src" directive serves as a fallback for the other CSP fetch directives.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src
    policy_values = csp_dict.get(policy_name) or csp_dict["default-src"]

    # If the tested element is default-src or script-src, we must ensure that none of this unsafe values are present
    if policy_name in ["default-src", "script-src"]:
        if any(unsafe_value in policy_values for unsafe_value in CSP_CHECK_LISTS[policy_name]):
            return 0
    # If the tested element is none of the previous list, we must ensure that one of this safe values is present
    else:
        if any(safe_value in policy_values for safe_value in CSP_CHECK_LISTS[policy_name]):
            return 1
        return 0

    return 1


def has_strong_csp(response: Response, page: Html) -> bool:
    """Check if the response has a CSP header that may be difficult to bypass (not weak)"""
    csp_string = get_csp_header(response) or get_csp_meta(page)
    if not csp_string:
        return False

    csp_dict = csp_header_to_dict(csp_string)
    if check_policy_values("script-src", csp_dict) == 1:
        return True

    return False
