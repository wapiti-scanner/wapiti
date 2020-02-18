#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2017-2020 Nicolas Surribas
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
import os
import json
import sqlite3
from collections import namedtuple

from wapitiCore.net import web


Payload = namedtuple("Payload", "evil_request,original_request,category,level,parameter,info,type")


class SqlitePersister:
    """This class makes the persistence tasks for persisting the crawler parameters
    in other to can continue the process in the future.
    """

    CRAWLER_DATA_DIR_NAME = "scans"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
    BASE_DIR = os.path.join(HOME_DIR, ".wapiti")
    CRAWLER_DATA_DIR = os.path.join(BASE_DIR, CRAWLER_DATA_DIR_NAME)

    ROOT_URL = "rootURL"
    TO_BROWSE = "toBrowse"
    BROWSED = "browsed"
    RESOURCE = "resource"
    METHOD = "method"
    PATH = "path"
    INPUT = "input"
    INPUT_NAME = "name"
    INPUT_VALUE = "value"
    HEADERS = "headers"
    HEADER = "header"
    HEADER_NAME = "name"
    HEADER_VALUE = "value"
    ENCODING = "encoding"
    ENCTYPE = "enctype"
    REFERER = "referer"
    GET_PARAMS = "get_params"
    POST_PARAMS = "post_params"
    FILE_PARAMS = "file_params"
    DEPTH = "depth"

    def __init__(self, output_file: str):
        # toBrowse can contain GET and POST resources
        self.to_browse = []
        # browsed contains only GET resources
        self.browsed_links = []
        # forms contains only POST resources
        self.browsed_forms = []
        self.uploads = []
        self.headers = {}
        self.root_url = ""

        self.tag = ""
        self.array = None

        self.method = ""
        self.path = ""
        self.encoding = ""
        self.enctype = "application/x-www-form-urlencoded"
        self.referer = ""
        self.get_params = []
        self.post_params = []
        self.file_params = []
        self.depth = 0
        self.output_file = output_file

        must_create = not os.path.exists(self.output_file)
        self._conn = sqlite3.connect(self.output_file)

        cursor = self._conn.cursor()

        if must_create:
            cursor.execute("""CREATE TABLE scan_infos (key TEXT, value TEXT)""")
            cursor.execute(
                """CREATE TABLE paths (
                     path_id INTEGER PRIMARY KEY,
                     path TEXT,
                     method TEXT,
                     enctype TEXT,
                     depth INTEGER,
                     encoding TEXT,
                     http_status INTEGER,
                     headers TEXT,
                     referer TEXT,
                     evil INTEGER
                )"""
            )

            cursor.execute(
                """CREATE TABLE params (
                    path_id INTEGER,
                    type TEXT,
                    param_order INTEGER,
                    name TEXT,
                    value1 TEXT,
                    value2 TEXT,
                    meta TEXT,
                    FOREIGN KEY(path_id) REFERENCES paths(path_id)
                )"""
            )

            cursor.execute(
                """CREATE TABLE attack_log (path_id INTEGER, module_name TEXT)"""
            )

            cursor.execute(
                """CREATE TABLE payloads (
                    evil_path INTEGER PRIMARY KEY,
                    original_path INTEGER,
                    category TEXT,
                    level INTEGER,
                    parameter TEXT,
                    info TEXT,
                    type TEXT
                )"""
            )

            self._conn.commit()

    def close(self):
        self._conn.close()

    def set_root_url(self, root_url):
        cursor = self._conn.cursor()
        cursor.execute("""INSERT INTO scan_infos VALUES (?, ?)""", ("root_url", root_url))
        self._conn.commit()
        self.root_url = root_url

    def get_root_url(self):
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM scan_infos WHERE key = 'root_url'")
        return cursor.fetchone()[0]

    def set_to_browse(self, to_browse):
        self._set_paths(to_browse)

    def get_to_browse(self):
        yield from self._get_paths(method=None, crawled=False)

    def _set_paths(self, paths):
        cursor = self._conn.cursor()
        for http_resource in paths:
            cursor.execute(
                """INSERT INTO paths VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    None,
                    http_resource.path,
                    http_resource.method,
                    http_resource.enctype,
                    http_resource.link_depth,
                    http_resource.encoding,
                    http_resource.status if isinstance(http_resource.status, int) else None,
                    None if http_resource.headers is None else json.dumps(dict(http_resource.headers)),
                    http_resource.referer,
                    0
                )
            )
            path_id = cursor.lastrowid
            for i, (k, v) in enumerate(http_resource.get_params):
                cursor.execute(
                    """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (path_id, "GET", i, k, v, None, None)
                )

            post_params = http_resource.post_params
            if isinstance(post_params, list):
                for i, (k, v) in enumerate(http_resource.post_params):
                    cursor.execute(
                        """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (path_id, "POST", i, k, v, None, None)
                    )
            elif len(post_params):
                cursor.execute(
                    """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (path_id, "POST", 0, "__RAW__", post_params, None, None)
                )

            for i, (k, v) in enumerate(http_resource.file_params):
                # v kill be something like ['pix.gif', 'GIF89a', 'image/gif']
                # just keep the file name
                if len(v) == 3:
                    meta = v[2]
                else:
                    meta = None
                cursor.execute(
                    """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (path_id, "FILE", i, k, v[0], v[1], meta)
                )
        self._conn.commit()

    def add_request(self, link):
        self._set_paths([link])

    def _get_paths(self, path=None, method=None, crawled: bool = True, attack_module: str = "", evil: bool = False):
        cursor = self._conn.cursor()

        conditions = ["evil = ?"]
        args = [int(evil)]

        if path and isinstance(path, str):
            conditions.append("path = ?")
            args.append(path)

        if method in ("GET", "POST"):
            conditions.append("method = ?")
            args.append(method)

        if crawled:
            conditions.append("headers IS NOT NULL")

        conditions = " AND ".join(conditions)
        conditions = "WHERE " + conditions

        cursor.execute("SELECT * FROM paths {} ORDER BY path".format(conditions), args)

        for row in cursor.fetchall():
            path_id = row[0]

            if attack_module:
                # Exclude requests matching the attack module, we want requests that aren't attacked yet
                cursor.execute(
                    "SELECT * FROM attack_log WHERE path_id = ? AND module_name = ? LIMIT 1",
                    (path_id, attack_module)
                )

                if cursor.fetchone():
                    continue

            get_params = []
            post_params = []
            file_params = []

            for param_row in cursor.execute(
                    (
                            "SELECT type, name, value1, value2, meta "
                            "FROM params "
                            "WHERE path_id = ? "
                            "ORDER BY type, param_order"
                    ),
                    (path_id, )
            ):
                name = param_row[1]
                value1 = param_row[2]

                if param_row[0] == "GET":
                    get_params.append([name, value1])
                elif param_row[0] == "POST":
                    if name == "__RAW__" and not post_params:
                        # First POST parameter is __RAW__, it should mean that we have raw content
                        post_params = value1
                    elif isinstance(post_params, list):
                        post_params.append([name, value1])
                elif param_row[0] == "FILE":
                    if param_row[4]:
                        file_params.append([name, [value1, param_row[3], param_row[4]]])
                    else:
                        file_params.append([name, [value1, param_row[3]]])
                else:
                    raise ValueError("Unknown param type {}".format(param_row[0]))

            http_res = web.Request(
                row[1],
                method=row[2],
                encoding=row[5],
                enctype=row[3],
                referer=row[8],
                get_params=get_params,
                post_params=post_params,
                file_params=file_params
            )

            if row[6]:
                http_res.status = row[6]

            if row[7]:
                http_res.set_headers(json.loads(row[7]))

            http_res.link_depth = row[4]
            http_res.path_id = path_id

            yield http_res

    def get_links(self, path=None, attack_module: str = ""):
        yield from self._get_paths(path=path, method="GET", crawled=True, attack_module=attack_module)

    def get_forms(self, attack_module: str = ""):
        yield from self._get_paths(method="POST", crawled=True, attack_module=attack_module)

    def count_paths(self) -> int:
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(path_id) from paths WHERE evil = 0")
        return cursor.fetchone()[0]

    def set_attacked(self, path_id, module_name):
        cursor = self._conn.cursor()
        cursor.execute("INSERT INTO attack_log VALUES (?, ?)", (path_id, module_name))
        self._conn.commit()

    def count_attacked(self, module_name) -> int:
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(path_id) from attack_log WHERE module_name = ?", (module_name, ))
        return cursor.fetchone()[0]

    def has_scan_finished(self):
        cursor = self._conn.cursor()
        cursor.execute("SELECT path_id FROM paths WHERE headers IS NULL LIMIT 1")
        if cursor.fetchone():
            return False
        return True

    def has_scan_started(self) -> bool:
        cursor = self._conn.cursor()
        cursor.execute("SELECT path_id FROM paths LIMIT 1")
        if cursor.fetchone():
            return True
        return False

    def have_attacks_started(self) -> bool:
        cursor = self._conn.cursor()
        cursor.execute("SELECT path_id FROM attack_log LIMIT 1")
        if cursor.fetchone():
            return True
        return False

    def add_payload(
            self, request_id: int, payload_type: str, category=None, level=0, request=None, parameter="", info=""):
        cursor = self._conn.cursor()

        cursor.execute(
            """INSERT INTO paths VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                None,
                request.path,
                request.method,
                request.enctype,
                request.link_depth,
                request.encoding,
                request.status if isinstance(request.status, int) else None,
                None if request.headers is None else json.dumps(dict(request.headers)),
                request.referer,
                1
            )
        )

        # path_id is the ID of the evil path
        path_id = cursor.lastrowid
        for i, (k, v) in enumerate(request.get_params):
            cursor.execute(
                """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (path_id, "GET", i, k, v, None, None)
            )

        post_params = request.post_params
        if isinstance(post_params, list):
            for i, (k, v) in enumerate(request.post_params):
                cursor.execute(
                    """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (path_id, "POST", i, k, v, None, None)
                )
        elif len(post_params):
            cursor.execute(
                """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (path_id, "POST", 0, "__RAW__", post_params, None, None)
            )

        for i, (k, v) in enumerate(request.file_params):
            if len(v) == 3:
                meta = v[2]
            else:
                meta = None

            cursor.execute(
                """INSERT INTO params VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (path_id, "FILE", i, k, v[0], v[1], meta)
            )

        # request_id is the ID of the original (legit) request
        cursor.execute(
            "INSERT INTO payloads VALUES (?, ?, ?, ?, ?, ?, ?)",
            (path_id, request_id, category, level, parameter, info, payload_type)
        )
        self._conn.commit()

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.add_payload(
            request_id,
            "anomaly",
            category,
            level,
            request,
            parameter,
            info
        )

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.add_payload(
            request_id,
            "vulnerability",
            category,
            level,
            request,
            parameter,
            info
        )

    def get_path_by_id(self, path_id):
        cursor = self._conn.cursor()

        cursor.execute("SELECT * FROM paths WHERE path_id = ? LIMIT 1", (path_id, ))

        row = cursor.fetchone()
        if not row:
            return None

        get_params = []
        post_params = []
        file_params = []

        for param_row in cursor.execute(
                (
                        "SELECT type, name, value1, value2, meta "
                        "FROM params "
                        "WHERE path_id = ? "
                        "ORDER BY type, param_order"
                ),
                (path_id, )
        ):
            name = param_row[1]
            value1 = param_row[2]

            if param_row[0] == "GET":
                get_params.append([name, value1])
            elif param_row[0] == "POST":
                if name == "__RAW__" and not post_params:
                    # First POST parameter is __RAW__, it should mean that we have raw content
                    post_params = value1
                elif isinstance(post_params, list):
                    post_params.append([name, value1])
            elif param_row[0] == "FILE":
                if param_row[4]:
                    file_params.append([name, [value1, param_row[3], param_row[4]]])
                else:
                    file_params.append([name, [value1, param_row[3]]])
            else:
                raise ValueError("Unknown param type {}".format(param_row[0]))

        request = web.Request(
            row[1],
            method=row[2],
            encoding=row[5],
            enctype=row[3],
            referer=row[8],
            get_params=get_params,
            post_params=post_params,
            file_params=file_params
        )

        if row[6]:
            request.status = row[6]

        if row[7]:
            request.set_headers(json.loads(row[7]))

        request.link_depth = row[4]
        request.path_id = path_id

        return request

    def get_payloads(self):
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM payloads")

        for row in cursor.fetchall():
            evil_id, original_id, category, level, parameter, info, payload_type = row

            evil_request = self.get_path_by_id(evil_id)
            original_request = self.get_path_by_id(original_id)

            yield Payload(evil_request, original_request, category, level, parameter, info, payload_type)

    def flush_session(self):
        self.flush_attacks()
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM paths")
        cursor.execute("DELETE FROM params")
        self._conn.commit()

    def flush_attacks(self):
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM attack_log")  # which module was launched on which URL
        cursor.execute("DELETE FROM payloads")  # informations on vulnerabilities and anomalies
        cursor.execute("DELETE FROM paths WHERE evil = 1")  # Evil requests
        # Remove params tied to deleted requests
        cursor.execute("DELETE FROM params WHERE path_id NOT IN (SELECT path_id FROM paths)")
        self._conn.commit()

    def delete_path_by_id(self, path_id):
        cursor = self._conn.cursor()
        # First remove all references to that path then remove it
        cursor.execute("DELETE FROM payloads WHERE evil_path = ? OR original_path = ?", (path_id, path_id))
        cursor.execute("DELETE FROM attack_log WHERE path_id = ?", (path_id, ))
        cursor.execute("DELETE FROM params WHERE path_id = ?", (path_id, ))
        cursor.execute("DELETE FROM paths WHERE path_id = ?", (path_id, ))
        self._conn.commit()

    def get_big_requests_ids(self, params_count: int) -> list:
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT path_id, count(*) as params_count FROM params GROUP BY path_id HAVING params_count > ?",
            (params_count, )
        )

        path_ids = set()
        for row in cursor.fetchall():
            path_id, count = row
            path_ids.add(path_id)

        return list(path_ids)

    def remove_big_requests(self, params_count: int) -> int:
        path_ids = self.get_big_requests_ids(params_count)

        for path_id in path_ids:
            self.delete_path_by_id(path_id)
        return len(path_ids)
