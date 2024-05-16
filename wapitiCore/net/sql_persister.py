#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2017-2023 Nicolas Surribas
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
import json
import os
from collections import namedtuple
from typing import AsyncIterator, Iterable, List, Optional, Sequence, Tuple

from aiocache import cached
import httpx
from sqlalchemy import (Boolean, Column, ForeignKey, Integer, MetaData,
                        PickleType, String, Table, Text, LargeBinary, and_,
                        literal_column, or_, select)
from sqlalchemy.sql.functions import max as sql_max
from sqlalchemy.sql.functions import count as sql_count
from sqlalchemy.ext.asyncio import create_async_engine
from wapitiCore.net import Request, Response

Payload = namedtuple("Payload", "evil_request,original_request,category,level,parameter,info,type,wstg,module,response")


class SqlPersister:
    """This class makes the persistence tasks for persisting the crawler parameters
    in other to can continue the process in the future.
    """

    CRAWLER_DATA_DIR_NAME = "scans"
    CONFIG_DIR_NAME = "config"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    BASE_DIR = os.path.join(HOME_DIR, ".wapiti")
    CRAWLER_DATA_DIR = os.path.join(BASE_DIR, CRAWLER_DATA_DIR_NAME)
    CONFIG_DIR = os.path.join(BASE_DIR, CONFIG_DIR_NAME)

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

    def __init__(self, output_file: str, table_prefix: str = ""):
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

        self._must_create = not os.path.exists(self.output_file)
        self._engine = create_async_engine(f'sqlite+aiosqlite:///{self.output_file}')
        self.register_database_model(table_prefix)
        # May be of interest: https://charlesleifer.com/blog/going-fast-with-sqlite-and-python/

    def register_database_model(self, table_prefix: str):
        self.metadata = MetaData()

        self.scan_infos = Table(
            f"{table_prefix}scan_infos", self.metadata,
            Column("key", String(255), nullable=False),
            Column("value", Text, nullable=False)  # We keep the root URL here. With URL scope it may be big
        )

        self.paths = Table(
            f"{table_prefix}paths", self.metadata,
            Column("path_id", Integer, primary_key=True),
            Column("path", Text, nullable=False),  # URL, can be huge
            Column("method", String(length=16), nullable=False),  # HTTP method
            Column("enctype", String(length=255), nullable=False),  # HTTP request encoding (like multipart...)
            Column("depth", Integer, nullable=False),
            Column("encoding", String(length=255)),  # page encoding (like UTF-8...)
            Column("headers", PickleType),  # Pickled sent HTTP headers, can be huge
            Column("referer", Text),  # Another URL so potentially huge
            Column("evil", Boolean, nullable=False),
            Column("response_id", None, ForeignKey(f"{table_prefix}responses.response_id"), nullable=True),
        )

        self.params = Table(
            f"{table_prefix}params", self.metadata,
            Column("param_id", Integer, primary_key=True),
            Column("path_id", None, ForeignKey(f"{table_prefix}paths.path_id")),
            Column("type", String(length=16), nullable=False),  # HTTP method or "FILE" for multipart
            Column("position", Integer, nullable=False),
            Column("name", Text, nullable=False),  # Name of the parameter. Encountered some above 1000 characters
            Column("value1", Text),  # Can be really huge
            Column("value2", Text),  # File content. Will be short most of the time but we plan on more usage
            Column("meta", String(255))  # File mime-type
        )

        self.payloads = Table(
            f"{table_prefix}payloads", self.metadata,
            Column("evil_path_id", None, ForeignKey(f"{table_prefix}paths.path_id"), nullable=False),
            Column("original_path_id", None, ForeignKey(f"{table_prefix}paths.path_id"), nullable=False),
            Column("module", String(255), nullable=False),
            Column("category", String(255), nullable=False),  # Vulnerability category, should not be that long
            Column("level", Integer, nullable=False),
            Column("parameter", Text, nullable=False),  # Vulnerable parameter, can be huge
            Column("info", Text, nullable=False),
            # Vulnerability description. If it contains the parameter name then huge.
            Column("type", String(255), nullable=False),  # Something like additional/anomaly/vulnerability
            Column("wstg", String(255), nullable=False),  # Something like additional/anomaly/vulnerability
            Column("response_id", None, ForeignKey(f"{table_prefix}responses.response_id"), nullable=True)
        )

        self.attack_logs = Table(
            f"{table_prefix}attack_logs", self.metadata,
            Column("path_id", None, ForeignKey(f"{table_prefix}paths.path_id"), nullable=False),
            Column("module", String(255), nullable=False)
        )

        self.responses = Table(
            f"{table_prefix}responses", self.metadata,
            Column("response_id", Integer, primary_key=True),
            Column("url", Text, nullable=False),  # URL, can be huge
            Column("status_code", Integer, nullable=False),  # HTTP status code
            Column("headers", PickleType),  # Pickled HTTP headers, can be huge
            Column("body", LargeBinary, nullable=False)  # base64 body
        )

    async def create(self):
        if self._must_create:
            async with self._engine.begin() as conn:
                await conn.run_sync(self.metadata.create_all)

    async def close(self):
        await self._engine.dispose()

    async def set_root_url(self, root_url: str):
        async with self._engine.begin() as conn:
            await conn.execute(self.scan_infos.insert().values(
                key="root_url",
                value=root_url
            ))
        self.root_url = root_url

    @cached()
    async def get_root_url(self) -> str:
        statement = select(self.scan_infos).where(self.scan_infos.c.key == "root_url").limit(1)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            return result.fetchone().value

    async def set_to_browse(self, to_browse: Sequence[Request]):
        await self.save_requests([(request, None) for request in to_browse])

    async def get_to_browse(self) -> AsyncIterator[Request]:
        async for path, __ in self._get_paths(method=None, crawled=False):
            yield path

    async def save_requests(self, paths_list: List[Tuple[Request, Optional[Response]]]):
        if not paths_list:
            return

        if len(paths_list) == 1:
            # Save the unique request and response objects
            await self.save_request(paths_list[0][0], paths_list[0][1])
            return

        bigest_id = 0
        all_path_values = []
        all_param_values = []

        async with self._engine.begin() as conn:
            response_ids = [await self.save_response(response) for _, response in paths_list]

            for (http_resource, _), response_id in zip(paths_list, response_ids):
                if http_resource.path_id:
                    # Request was already saved but not fetched, just update to set HTTP code and headers
                    statement = self.paths.update().where(
                        self.paths.c.path_id == http_resource.path_id
                    ).values(
                        headers=http_resource.headers,
                        response_id=response_id
                    )
                    await conn.execute(statement)
                    continue

                if bigest_id == 0:
                    # This is a trick to be able to insert all paths and params in bulk
                    # instead of inserting path and get the new returned ID to then insert params
                    result = await conn.execute(select(sql_max(self.paths.c.path_id)))
                    result = result.scalar()
                    if result is not None:
                        bigest_id = result

                bigest_id += 1

                # Save the request along with its parameters
                # Beware: https://docs.sqlalchemy.org/en/14/core/tutorial.html#executing-multiple-statements
                # When executing multiple sets of parameters, each dictionary must have the same set of keys;
                # i.e. you can't have fewer keys in some dictionaries than others.
                # This is because the Insert statement is compiled against the first dictionary in the list,
                # and it’s assumed that all subsequent argument dictionaries are compatible with that statement.
                all_path_values.append(
                    {
                        "path_id": bigest_id,
                        "path": http_resource.path,
                        "method": http_resource.method,
                        "enctype": http_resource.enctype,
                        "depth": http_resource.link_depth,
                        "encoding": http_resource.encoding,
                        "headers": http_resource.headers,
                        "referer": http_resource.referer,
                        "response_id": response_id,
                        "evil": False
                    }
                )

                for i, (get_param_key, get_param_value) in enumerate(http_resource.get_params):
                    all_param_values.append(
                        {
                            "path_id": bigest_id,
                            "type": "GET",
                            "position": i,
                            "name": get_param_key,
                            "value1": get_param_value,
                            "value2": None,
                            "meta": None
                        }
                    )

                post_params = http_resource.post_params
                if isinstance(post_params, list):
                    for i, (post_param_key, post_param_value) in enumerate(http_resource.post_params):
                        all_param_values.append(
                            {
                                "path_id": bigest_id,
                                "type": "POST",
                                "position": i,
                                "name": post_param_key,
                                "value1": post_param_value,
                                "value2": None,
                                "meta": None
                            }
                        )
                elif post_params:
                    all_param_values.append(
                        {
                            "path_id": bigest_id,
                            "type": "POST",
                            "position": 0,
                            "name": "__RAW__",
                            "value1": post_params,
                            "value2": None,
                            "meta": None
                        }
                    )

                for i, (file_param_key, file_param_value) in enumerate(http_resource.file_params):
                    # file_param_value will be something like ['pix.gif', 'GIF89a', 'image/gif']
                    # just keep the file name
                    if len(file_param_value) == 3:
                        meta = file_param_value[2]
                    else:
                        meta = None

                    all_param_values.append(
                        {
                            "path_id": bigest_id,
                            "type": "FILE",
                            "position": i,
                            "name": file_param_key,
                            "value1": file_param_value[0],
                            "value2": file_param_value[1],
                            "meta": meta
                        }
                    )

            if all_path_values:
                await conn.execute(self.paths.insert(), all_path_values)

                if all_param_values:
                    await conn.execute(self.params.insert(), all_param_values)

    async def save_response(self, response: Response) -> Optional[int]:
        if not response:
            return None

        statement = self.responses.insert().values(
            url=response.url,
            status_code=response.status,
            body=response.bytes,
            headers=response.headers
        )
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            return result.inserted_primary_key[0]

    async def save_request(self, http_resource: Request, response: Response = None):
        async with self._engine.begin() as conn:
            if http_resource.path_id:
                # Request was already saved but not fetched, just update to set HTTP code and headers
                statement = self.paths.update().where(
                    self.paths.c.path_id == http_resource.path_id
                ).values(
                    headers=http_resource.headers
                )
                await conn.execute(statement)
                return

            # We should never have a situation where we overwrite an existing response ID because a request can only be
            # saved once without response (from the to_browse list) and once when crawled. After, the request should be
            # removed as a duplicate by the Explorer class.
            response_id = await self.save_response(response)

            # as we have a unique request let's do insertion the classic way
            statement = self.paths.insert().values(
                path=http_resource.path,
                method=http_resource.method,
                enctype=http_resource.enctype,
                depth=http_resource.link_depth,
                encoding=http_resource.encoding,
                headers=http_resource.headers,
                referer=http_resource.referer,
                response_id=response_id,
                evil=False
            )

            result = await conn.execute(statement)

            path_id = result.inserted_primary_key[0]
            all_values = []
            for i, (get_param_key, get_param_value) in enumerate(http_resource.get_params):
                all_values.append(
                    {
                        "path_id": path_id,
                        "type": "GET",
                        "position": i,
                        "name": get_param_key,
                        "value1": get_param_value,
                        "value2": None,
                        "meta": None
                    }
                )

            post_params = http_resource.post_params
            if isinstance(post_params, list):
                for i, (post_param_key, post_param_value) in enumerate(http_resource.post_params):
                    all_values.append(
                        {
                            "path_id": path_id,
                            "type": "POST",
                            "position": i,
                            "name": post_param_key,
                            "value1": post_param_value,
                            "value2": None,
                            "meta": None
                        }
                    )
            elif post_params:
                all_values.append(
                    {
                        "path_id": path_id,
                        "type": "POST",
                        "position": 0,
                        "name": "__RAW__",
                        "value1": post_params,
                        "value2": None,
                        "meta": None
                    }
                )

            for i, (file_param_key, file_param_value) in enumerate(http_resource.file_params):
                # file_param_value will be something like ['pix.gif', 'GIF89a', 'image/gif']
                # just keep the file name
                if len(file_param_value) == 3:
                    meta = file_param_value[2]
                else:
                    meta = None

                all_values.append(
                    {
                        "path_id": path_id,
                        "type": "FILE",
                        "position": i,
                        "name": file_param_key,
                        "value1": file_param_value[0],
                        "value2": file_param_value[1],
                        "meta": meta
                    }
                )

            if all_values:
                await conn.execute(self.params.insert(), all_values)

    async def _get_paths(
            self, path=None, method=None, crawled: bool = True, module: str = "", evil: bool = False
    ) -> AsyncIterator[Tuple[Request, Response]]:
        conditions = [self.paths.c.evil == evil]

        if path and isinstance(path, str):
            conditions.append(self.paths.c.path == path)

        if method in ("GET", "POST"):
            conditions.append(self.paths.c.method == method)

        if crawled:
            # Bellow is sqlalchemy syntax, do not replace the comparison
            # pylint: disable=singleton-comparison
            conditions.append(self.paths.c.headers != None)

        async with self._engine.begin() as conn:
            result = await conn.execute(select(self.paths).where(and_(True, *conditions)).order_by(self.paths.c.path))

        for row in result.fetchall():
            path_id = row[0]
            response_id = row[9]

            if module:
                # Exclude requests matching the attack module, we want requests that aren't attacked yet
                statement = select(self.attack_logs).where(
                    self.attack_logs.c.path_id == path_id,
                    self.attack_logs.c.module == module
                ).limit(1)
                async with self._engine.begin() as conn:
                    result = await conn.execute(statement)

                if result.fetchone():
                    continue

            get_params = []
            post_params = []
            file_params = []

            statement = select(
                self.params.c.type, self.params.c.name, self.params.c.value1, self.params.c.value2, self.params.c.meta
            ).where(self.params.c.path_id == path_id).order_by(self.params.c.type, self.params.c.position)

            async with self._engine.begin() as conn:
                async_result = await conn.stream(statement)

                async for param_row in async_result:
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
                            file_params.append([name, (value1, param_row[3], param_row[4])])
                        else:
                            file_params.append([name, (value1, param_row[3])])
                    else:
                        raise ValueError(f"Unknown param type {param_row[0]}")

                request = Request(
                    row[1],
                    method=row[2],
                    encoding=row[5],
                    enctype=row[3],
                    referer=row[7],
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params
                )

                if row[6]:
                    request.set_headers(row[6])

                request.link_depth = row[4]
                request.path_id = path_id
                response = await self.get_response_by_id(response_id)

                yield request, response

    async def get_links(self, path=None, attack_module: str = "") -> AsyncIterator[Tuple[Request, Response]]:
        async for request, response in self._get_paths(path=path, method="GET", crawled=True, module=attack_module):
            yield request, response

    async def get_forms(self, path=None, attack_module: str = "") -> AsyncIterator[Tuple[Request, Response]]:
        async for request, response in self._get_paths(path=path, method="POST", crawled=True, module=attack_module):
            yield request, response

    async def get_all_paths(self) -> List:
        statement = select(
            self.paths,
            self.responses.c.status_code,
            self.responses.c.body,
            self.responses.c.headers.label("response_headers")
        ).select_from(
            self.paths.join(
                self.responses,
                self.paths.c.response_id == self.responses.c.response_id,
            )
        )

        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            return [{
                "request": {
                    "url": row.path,
                    "method": row.method,
                    "headers": [[key, value] for key, value in (row.headers or {}).items()],
                    "referer": row.referer,
                    "enctype": row.enctype,
                    "encoding": row.encoding,
                    "depth": row.depth,
                },
                "response": {
                    "status_code": row.status_code,
                    "body": row.body,
                    "headers": [[key, value] for key, value in (row.response_headers or {}).items()]
                },
            } for row in result.fetchall()]

    async def get_necessary_paths(self) -> List:
        requests = []
        async for request, response in self._get_paths(crawled=False):
            requests.append({"request": {"url": request.url, "method": request.method,
                                         "post_params": request.post_params,
                                         "status_code": response.status if response else None}})
        return requests

    async def count_paths(self) -> int:
        statement = select(sql_count(self.paths.c.path_id)).where(~self.paths.c.evil)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            return result.fetchone()[0]

    async def set_attacked(self, path_ids: Iterable, module_name: str):
        if not path_ids:
            return

        async with self._engine.begin() as conn:
            all_values = [
                {"path_id": path_id, "module": module_name} for path_id in path_ids
            ]
            await conn.execute(self.attack_logs.insert(), all_values)

    async def count_attacked(self, module_name) -> int:
        statement = select(sql_count(self.attack_logs.c.path_id)).where(self.attack_logs.c.module == module_name)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            return result.fetchone()[0]

    async def has_scan_finished(self) -> bool:
        # If we have a path without headers set then the scan is not finished
        # Bellow is sqlalchemy syntax, do not replace the comparison
        # pylint: disable=singleton-comparison
        statement = select(self.paths.c.path_id).where(self.paths.c.headers == None).limit(1)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            if result.fetchone():
                return False

        return True

    async def has_scan_started(self) -> bool:
        statement = select(self.paths.c.path_id).limit(1)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            if result.fetchone():
                return True

            return False

    async def have_attacks_started(self) -> bool:
        statement = select(self.attack_logs.c.path_id).limit(1)
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            if result.fetchone():
                return True

            return False

    async def add_payload(
            self,
            request_id: int,
            payload_type: str,
            module: str,
            category: Optional[str] = None,
            level: int = 0,
            request: Request = None,
            parameter: str = "",
            info: str = "",
            wstg: Optional[List[str]] = None,
            response: Response = None
    ):

        response_id = await self.save_response(response)

        # Save the request along with its parameters
        statement = self.paths.insert().values(
            path=request.path,
            method=request.method,
            enctype=request.enctype,
            depth=request.link_depth,
            encoding=request.encoding,
            headers=request.headers,
            referer=request.referer,
            response_id=response_id,
            evil=True,
        )
        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
        # path_id is the ID of the evil path
        path_id = result.inserted_primary_key[0]

        all_values = []
        for i, (get_param_key, get_param_value) in enumerate(request.get_params):
            all_values.append(
                {
                    "path_id": path_id,
                    "type": "GET",
                    "position": i,
                    "name": get_param_key,
                    "value1": get_param_value,
                    "value2": None,
                    "meta": None
                }
            )

        if isinstance(request.post_params, list):
            for i, (post_param_key, post_param_value) in enumerate(request.post_params):
                all_values.append(
                    {
                        "path_id": path_id,
                        "type": "POST",
                        "position": i,
                        "name": post_param_key,
                        "value1": post_param_value,
                        "value2": None,
                        "meta": None
                    }
                )
        elif request.post_params:
            all_values.append(
                {
                    "path_id": path_id,
                    "type": "POST",
                    "position": 0,
                    "name": "__RAW__",
                    "value1": request.post_params,
                    "value2": None,
                    "meta": None
                }
            )

        for i, (file_param_key, file_param_value) in enumerate(request.file_params):
            if len(file_param_value) == 3:
                meta = file_param_value[2]
            else:
                meta = None

            all_values.append(
                {
                    "path_id": path_id,
                    "type": "FILE",
                    "position": i,
                    "name": file_param_key,
                    "value1": file_param_value[0],
                    "value2": file_param_value[1],
                    "meta": meta
                }
            )

        if all_values:
            async with self._engine.begin() as conn:
                await conn.execute(self.params.insert(), all_values)

        # request_id is the ID of the original (legit) request
        statement = self.payloads.insert().values(
            evil_path_id=path_id,
            original_path_id=request_id,
            module=module,
            category=category,
            level=level,
            parameter=parameter,
            info=info,
            type=payload_type,
            wstg=json.dumps(wstg or []),
            response_id=response_id
        )
        async with self._engine.begin() as conn:
            await conn.execute(statement)

    async def get_response_by_id(self, response_id: str) -> Optional[Response]:
        if not response_id:
            return None
        response_id = int(response_id)

        async with self._engine.begin() as conn:
            result = await conn.execute(
                select(self.responses).where(self.responses.c.response_id == response_id).limit(1)
            )

        row = result.fetchone()
        if not row:
            return None

        headers = row.headers
        if "content-encoding" in headers:
            # httpx will try to decompress the content if it sees the following header, leading to an exception
            del headers["content-encoding"]

        response = Response(
            httpx.Response(
                row.status_code,
                headers=headers,
                content=row.body
            ),
            row.url,
        )

        return response

    async def get_path_by_id(self, path_id):
        path_id = int(path_id)
        async with self._engine.begin() as conn:
            result = await conn.execute(select(self.paths).where(self.paths.c.path_id == path_id).limit(1))

        row = result.fetchone()
        if not row:
            return None

        get_params = []
        post_params = []
        file_params = []

        statement = select(
            self.params.c.type, self.params.c.name, self.params.c.value1, self.params.c.value2, self.params.c.meta
        ).where(self.params.c.path_id == path_id).order_by(self.params.c.type, self.params.c.position)

        async with self._engine.begin() as conn:
            async_result = await conn.stream(statement)

            async for param_row in async_result:
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
                        file_params.append([name, (value1, param_row[3], param_row[4])])
                    else:
                        file_params.append([name, (value1, param_row[3])])
                else:
                    raise ValueError(f"Unknown param type {param_row[0]}")

            request = Request(
                row[1],
                method=row[2],
                encoding=row[5],
                enctype=row[3],
                referer=row[7],
                get_params=get_params,
                post_params=post_params,
                file_params=file_params
            )

            if row[6]:
                request.set_headers(row[6])

            request.link_depth = row[4]
            request.path_id = path_id

            return request

    async def get_payloads(self) -> AsyncIterator[Payload]:
        async with self._engine.begin() as conn:
            result = await conn.execute(select(self.payloads))

        for row in result.fetchall():
            evil_id, original_id, module, category, level, parameter, info, payload_type, wstg, response_id = row

            evil_request = await self.get_path_by_id(evil_id)
            original_request = await self.get_path_by_id(original_id)
            response = await self.get_response_by_id(response_id)

            yield Payload(
                evil_request,
                original_request,
                category,
                level,
                parameter,
                info,
                payload_type,
                json.loads(wstg),
                module,
                response
            )

    async def flush_session(self):
        await self.flush_attacks()
        async with self._engine.begin() as conn:
            await conn.execute(self.paths.delete())
            await conn.execute(self.params.delete())

    async def flush_attacks(self):
        async with self._engine.begin() as conn:
            await conn.execute(self.attack_logs.delete())  # which module was launched on which URL
            await conn.execute(self.payloads.delete())  # information on vulnerabilities and anomalies
            # Bellow is sqlalchemy syntax, do not replace the comparison
            # pylint: disable=singleton-comparison
            await conn.execute(self.paths.delete().where(self.paths.c.evil == True))  # Evil requests
            # Remove params tied to deleted requests
            await conn.execute(self.params.delete().where(~self.params.c.path_id.in_(select(self.paths.c.path_id))))

    async def delete_path_by_id(self, path_id):
        # First remove all references to that path then remove it
        async with self._engine.begin() as conn:
            await conn.execute(
                self.payloads.delete().where(
                    or_(
                        self.payloads.c.evil_path_id == path_id,
                        self.payloads.c.original_path_id == path_id
                    )
                )
            )
            await conn.execute(self.attack_logs.delete().where(self.attack_logs.c.path_id == path_id))
            await conn.execute(self.params.delete().where(self.params.c.path_id == path_id))
            await conn.execute(self.paths.delete().where(self.paths.c.path_id == path_id))

    async def get_big_requests_ids(self, params_count: int) -> list:
        statement = select(
            self.params.c.path_id, sql_count(self.params.c.param_id).label("params_count")
        ).group_by("path_id").having(literal_column("params_count") > params_count)

        async with self._engine.begin() as conn:
            result = await conn.execute(statement)
            path_ids = set()
            for row in result.fetchall():
                path_id, __ = row
                path_ids.add(path_id)

            return list(path_ids)

    async def remove_big_requests(self, params_count: int) -> int:
        path_ids = await self.get_big_requests_ids(params_count)

        for path_id in path_ids:
            await self.delete_path_by_id(path_id)

        return len(path_ids)
