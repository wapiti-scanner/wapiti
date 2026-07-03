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

# A directive name is a sequence of ASCII letters, digits and dashes.
# Anything else (e.g. a value left orphan by a misplaced semicolon) is not a directive.
DIRECTIVE_NAME_REGEX = re.compile(r"^[a-z0-9-]+$")

CSP_CHECK_LISTS = {
    # As default-src is the fallback directive we may want to avoid those duplicates in the future
    "default-src": ["unsafe-inline", "data:", "http:", "https:", "*", "unsafe-eval"],
    "script-src": ["unsafe-inline", "data:", "http:", "https:", "*", "unsafe-eval"],
    "object-src": ["none"],
    "base-uri": ["none", "self"],
    "frame-ancestors": ["none", "self"],
    "form-action": ["none", "self"],
}

# Directives that do NOT fall back to default-src when they are omitted.
# default-src only acts as a fallback for the fetch directives; document and
# navigation directives (base-uri, frame-ancestors, form-action, ...) have no fallback.
CSP_NO_FALLBACK_DIRECTIVES = {"base-uri", "frame-ancestors", "form-action"}

# Every directive name defined by the CSP specification (Level 3), plus a few
# widely-encountered deprecated ones. Used to flag unknown or misspelled directives.
CSP_DIRECTIVES = {
    # Fetch directives
    "child-src", "connect-src", "default-src", "font-src", "frame-src",
    "img-src", "manifest-src", "media-src", "object-src", "prefetch-src",
    "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "worker-src",
    # Document directives
    "base-uri", "sandbox",
    # Navigation directives
    "form-action", "frame-ancestors", "navigate-to",
    # Reporting directives
    "report-uri", "report-to",
    # Directives without a source list
    "block-all-mixed-content", "upgrade-insecure-requests",
    "require-trusted-types-for", "trusted-types", "require-sri-for",
    # Deprecated but still encountered in the wild
    "referrer", "reflected-xss", "disown-opener", "plugin-types",
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
        policy_string = policy_string.strip()
        if not policy_string:
            # We reached the end or an empty segment
            continue

        parts = policy_string.split(" ", 1)
        # Directive names are case-insensitive
        policy_name = parts[0].lower()
        if not DIRECTIVE_NAME_REGEX.match(policy_name):
            # Malformed segment (e.g. a value orphaned by a misplaced semicolon)
            continue

        if len(parts) == 2:
            csp_dict[policy_name] = [value.strip("'") for value in POLICY_REGEX.findall(parts[1])]
        else:
            # Directive without a value (e.g. upgrade-insecure-requests)
            csp_dict[policy_name] = []

    return csp_dict


def check_policy_values(policy_name, csp_dict):
    """
    This function return the status of the tested element in the CSP as an int. Possible values:
    -1 : the element is missing in the CSP
    0  : the element is set, but his value is not secure
    1  : the element is set and his value is secure
    """

    # The HTTP CSP "default-src" directive serves as a fallback for the other CSP fetch directives only.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src
    # Document/navigation directives (base-uri, frame-ancestors, form-action) have no fallback.
    if policy_name in csp_dict:
        policy_values = csp_dict[policy_name]
    elif policy_name not in CSP_NO_FALLBACK_DIRECTIVES and "default-src" in csp_dict:
        policy_values = csp_dict["default-src"]
    else:
        return -1

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


def find_unknown_directives(csp_dict):
    """Return the list of directive names present in the CSP that are not part of the
    specification. Those are usually typos or misspelled directives, which are silently
    ignored by browsers and thus provide no protection at all."""
    return [name for name in csp_dict if name not in CSP_DIRECTIVES]


def has_strong_csp(response: Response, page: Html) -> bool:
    """Check if the response has a CSP header that may be difficult to bypass (not weak)"""
    csp_string = get_csp_header(response) or get_csp_meta(page)
    if not csp_string:
        return False

    csp_dict = csp_header_to_dict(csp_string)
    if check_policy_values("script-src", csp_dict) == 1:
        return True

    return False
