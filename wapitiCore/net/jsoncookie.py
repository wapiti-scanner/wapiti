#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2012-2023 Nicolas Surribas
# Copyright (C) 2020-2024 Cyberwatch
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
import json
import re
from http.cookiejar import Cookie, CookieJar

# Regex to check whether the domain returned by CookieJar is an IP address
# IPv6 addresses seems to have a ".local" suffix.
IP_REGEX = re.compile(r"^(?P<ip>(\d+\.\d+\.\d+.\d+)|(\[([\da-f:]+)\])(\.local)?)(?P<port>:\d+)?$")


class JsonCookie:
    """This class allows to store (and load) cookies in a JSON formatted file."""

    def __init__(self):
        self.cookiedict = None
        self.filename = None

    # return a dictionary on success, None on failure
    def load(self, filename):
        if not filename:
            return None
        self.filename = filename
        try:
            with open(filename, "r+", encoding='utf-8') as file_data:
                self.cookiedict = json.load(file_data)
        except (IOError, ValueError):
            with open(filename, "w+", encoding='utf-8') as file_data:
                self.cookiedict = {}
        return self.cookiedict

    def addcookies(self, cookie_jar: CookieJar):
        """Inject Cookies from a CookieJar into our JSON dictionary."""
        for cookie in cookie_jar:
            search_ip = IP_REGEX.match(cookie.domain)
            if search_ip:
                # Match either an IPv4 address or an IPv6 address with a local suffix
                domain_key = search_ip.group("ip")
            else:
                domain_key = cookie.domain if cookie.domain[0] == '.' else '.' + cookie.domain

            if domain_key not in self.cookiedict.keys():
                self.cookiedict[domain_key] = {}

            if cookie.path not in self.cookiedict[domain_key].keys():
                self.cookiedict[domain_key][cookie.path] = {}

            print(cookie)
            cookie_attrs = {
                "value": cookie.value,
                "expires": cookie.expires,
                "secure": cookie.secure,
                "port": cookie.port,
                "version": cookie.version
            }
            self.cookiedict[domain_key][cookie.path][cookie.name] = cookie_attrs
        return True

    def cookiejar(self, domain):
        """Returns a cookielib.CookieJar object containing cookies matching the given domain."""
        cookie_jar = CookieJar()

        if not domain:
            return cookie_jar

        # Domain comes from a urlparse().netloc so we must take care of optional port number
        search_ip = IP_REGEX.match(domain)
        if search_ip:
            # IPv4 (ex: '127.0.0.1') or IPv6 (ex: '[::1]') address.
            # We must append the '.local' suffix pour IPv6 addresses.
            domain = search_ip.group("ip")
            if domain.startswith("[") and not domain.endswith(".local"):
                domain += ".local"
            matching_domains = [domain]
        else:
            domain = domain.split(":")[0]

            # For hostnames on local network we must add a 'local' tld (needed by cookielib)
            if '.' not in domain:
                domain += ".local"

            domain_key = domain if domain[0] == '.' else '.' + domain
            exploded = domain_key.split(".")
            parent_domains = ["." + ".".join(exploded[x:]) for x in range(1, len(exploded) - 1)]
            matching_domains = [d for d in parent_domains if d in self.cookiedict]

        if not matching_domains:
            return cookie_jar

        for dom in matching_domains:
            for path in self.cookiedict[dom]:
                for cookie_name, cookie_attrs in self.cookiedict[dom][path].items():
                    cookie = Cookie(
                        version=cookie_attrs["version"],
                        name=cookie_name,
                        value=cookie_attrs["value"],
                        port=None,
                        port_specified=False,
                        domain=dom,
                        domain_specified=True,
                        domain_initial_dot=False,
                        path=path,
                        path_specified=True,
                        secure=cookie_attrs["secure"],
                        expires=cookie_attrs["expires"],
                        discard=True,
                        comment=None,
                        comment_url=None,
                        rest={'HttpOnly': None},
                        rfc2109=False
                    )

                    if cookie_attrs["port"]:
                        cookie.port = cookie_attrs["port"]
                        cookie.port_specified = True

                    cookie_jar.set_cookie(cookie)
        return cookie_jar

    def delete(self, domain, path=None, key=None):
        if not domain:
            return False

        search_ip = IP_REGEX.match(domain)
        if search_ip:
            # IPv4 (ex: '127.0.0.1') or IPv6 (ex: '[::1]') address
            # We must append the '.local' suffix pour IPv6 addresses.
            domain = search_ip.group("ip")
            if domain.startswith("[") and not domain.endswith(".local"):
                domain += ".local"
        else:
            domain = domain.split(":")[0]
            # For hostnames on local network we must add a 'local' tld (needed by cookielib)
            if '.' not in domain:
                domain += ".local"
            domain = domain if domain[0] == '.' else '.' + domain

        if domain not in self.cookiedict.keys():
            return False

        if not path:
            # delete whole domain data
            self.cookiedict.pop(domain)
            return True

        # path asked for deletion... but does not exist
        if path not in self.cookiedict[domain].keys():
            return False

        if not key:
            # remove every data on the specified domain for the matching path
            self.cookiedict[domain].pop(path)
            return True

        if key in self.cookiedict[domain][path].keys():
            self.cookiedict[domain][path].pop(key)
            return True
        return False

    def dump(self):
        if not self.filename:
            return False
        with open(self.filename, "r+", encoding='utf-8') as file_data:
            file_data.seek(0)
            file_data.truncate()
            json.dump(self.cookiedict, file_data, indent=2)
        return True
