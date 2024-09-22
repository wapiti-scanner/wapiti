#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
import urllib.parse
from prance import ResolvingParser, ValidationError
from prance.util.formats import ParseError
from prance.util.url import ResolutionError

from wapitiCore.net import Request
from wapitiCore.main.log import logging


class Swagger:
    AUTOFILL_VALUES = {
        "file": ("pix.gif", b"GIF89a", "image/gif"),
        "integer": "1337",
        "number": "13.37",
        "string": "default",
        "time": "13:37",
        "date-time": "2024-08-16T16:03:08",
        "url": "https://wapiti-scanner.github.io/",
        "boolean": True,
        "object": {},
    }

    swagger_dict = None
    routes = None

    def __init__(self, swagger_url: str = None, base_url: str = None) -> None:
        if swagger_url:
            try:
                self.swagger_dict = ResolvingParser(swagger_url, backend='openapi-spec-validator',
                                                    strict=False, recursion_limit=5).specification
            except ParseError as e:
                logging.error("[-] Error: Swagger file format invalid : " + str(e.args[0]))
            except ValidationError as e:
                logging.error("[-] Error: Swagger file is not valid : " + str(e.args[0]) +
                              ". See https://swagger.io/specification/ for more information.")
            except AssertionError:
                logging.error("[-] Error: File not found")
            except ResolutionError:
                logging.error("[-] Error: Unable to resolve the swagger file")
        else:
            logging.error("[-] Error: No URL or file")

        if self.swagger_dict:
            self.routes = self._get_routes(self.swagger_dict, base_url)

    @staticmethod
    def _get_base_url(swagger_dict: dict, url: str) -> str:
        try:
            parsed_host = urllib.parse.urlparse(url)
            if 'servers' in swagger_dict:
                for server in swagger_dict['servers']:
                    if 'url' in server and server['url'] != "":
                        if server['url'].endswith("/"):
                            server['url'] = server['url'][:-1]
                        swagger_url = server['url']
                        if 'variables' in server:
                            for variable in server['variables']:
                                swagger_url = swagger_url.replace(
                                    "{" + variable + "}", server['variables'][variable]['default']
                                )
                        swagger_dict['basePath'] = ""
                        swagger_dict['host'] = swagger_url
                        return swagger_url
            if 'schemes' not in swagger_dict:
                # get http or https from url
                swagger_dict['schemes'] = parsed_host.scheme
            if 'host' not in swagger_dict:
                if url:
                    swagger_dict['host'] = parsed_host.hostname
                    if parsed_host.port:
                        swagger_dict['host'] += ":" + str(parsed_host.port)
                else:
                    swagger_dict['host'] = ""
            elif swagger_dict['host'] == "localhost" and url:
                swagger_dict['host'] = parsed_host.hostname
            if 'basePath' not in swagger_dict:
                swagger_dict['basePath'] = ""
            if 'https' in swagger_dict['schemes']:
                return 'https://' + swagger_dict['host'] + swagger_dict['basePath']
            return 'http://' + swagger_dict['host'] + swagger_dict['basePath']
        except ValueError as e:
            logging.error("[-] Error: Swagger file is not valid : " + str(e) +
                          ". See https://swagger.io/specification/ for more information.")
            base_url = parsed_host._replace(path="").geturl()
            swagger_dict["basePath"] = base_url
            return base_url

    @staticmethod
    def _check_properties(model_name: dict) -> dict:
        if "properties" in model_name:
            return model_name['properties']
        if "additionalProperties" in model_name:
            return model_name['additionalProperties']
        return model_name

    # Parse object in swagger file.
    # Replace all object by their type and all array by their type
    # according to their properties and definitions.
    # It will be easier to create request with default value.
    def _parse_object(self, model_name):
        model = {}
        for key in model_name:
            try:
                if 'type' in model_name[key]:
                    if 'object' in model_name[key]['type']:
                        ref = self._check_properties(model_name[key])
                        model[key] = self._parse_object(ref)
                        if 'type' in model[key]:
                            if model[key]['type'] == "array":
                                model[key] = {"array": model[key]['items']}
                            else:
                                model[key] = model[key]['type']
                    elif 'array' in model_name[key]['type']:
                        if 'type' in model_name[key]['items']:
                            model[key] = {"array": model_name[key]['items']['type']}
                            if 'object' in model_name[key]['items']['type']:
                                ref = self._check_properties(model_name[key]['items'])
                                model[key]["array"] = self._parse_object(ref)
                    else:
                        if 'format' in model_name[key] and 'date-time' in model_name[key]['format']:
                            model[key] = model_name[key]['format']
                        else:
                            model[key] = model_name[key]['type']
                else:
                    model[key] = model_name[key]
            except ValueError as e:
                logging.error("[-] Error: Swagger file is not valid : " + str(e) +
                              "\nSee https://swagger.io/specification/ for more information")
        return model

    def _check_params(self, params: dict) -> list:
        raws = []
        for param in params:
            raw = {}
            if 'in' in param or '/' in param:
                if '/' in param:
                    raw['in'] = "body"
                    param = params[param]
                else:
                    raw['in'] = param['in']
                if raw['in'] == "body" and 'schema' in param:
                    if 'type' in param['schema']:
                        if 'object' in param['schema']['type']:
                            ref = self._check_properties(param['schema'])
                            model = self._parse_object(ref)
                            raw['model'] = model
                        elif 'array' in param['schema']['type']:
                            if 'object' in param['schema']['items']['type']:
                                ref = self._check_properties(param['schema']['items'])
                                model = self._parse_object(ref)
                                raw['model'] = model
                        else:
                            raw['type'] = param['schema']['type']
            if 'type' in param:
                if param['type'] == "array":
                    if 'enum' in param['items']:
                        raw['type'] = {"enum": param['items']['enum']}
                    else:
                        raw['type'] = {"array": param['items']['type']}
                else:
                    raw['type'] = param['type']
            if 'name' in param:
                raw['name'] = param['name']
            if 'required' in param:
                raw['required'] = param['required']
            if raw:
                raws.append(raw)
        return raws

    @staticmethod
    def is_valid_url(url) -> bool:
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def _get_routes(self, swagger_dict: dict, base_url: str) -> dict:
        # We use the url from the -u unless the swagger file has one
        url = base_url
        request = {}
        base_path = self._get_base_url(swagger_dict, url)
        for path in swagger_dict['paths']:
            for method in swagger_dict['paths'][path]:
                if method == "parameters":
                    path = self._parse_parameters(swagger_dict['paths'][path][method], path)
                    continue
                route = method.upper() + " " + base_path + path
                params = self._get_parameters(swagger_dict, route, url)
                request[route] = []
                try:
                    if params:
                        request_route = {
                            "method": method.upper(),
                            "route": route.replace(method.upper() + ' ', ''),
                            'params': []
                        }

                        if 'requestBody' in params:
                            request_route['params'] += self._check_params(params['requestBody']['content'])

                        if 'parameters' in params:
                            request_route['params'] += self._check_params(params['parameters'])
                        request_route['params'] += self._check_params(params)
                        request[route].append(request_route)
                    else:
                        request_route = {"method": method.upper(), "route": route.replace(method.upper() + ' ', '')}
                        request[route].append(request_route)
                except KeyError as e:
                    logging.error("[-] Error: " + str(e))
        return request

    def _parse_parameters(self, params: list, route: str) -> str:
        for param in params:
            if not "type" in param:
                param["type"] = "string"
            if "in" in param:
                if param['in'] == "path":
                    route = route.replace("{" + param['name'] + "}", self.AUTOFILL_VALUES[param['type']])
                elif param['in'] == "query":
                    route += "&" + param['name'] + "=" + self.AUTOFILL_VALUES[param['type']]
        return route

    def _get_parameters(self, swagger_dict: dict, route: str, url: str) -> list:
        try:
            base_path = self._get_base_url(swagger_dict, url)
            route = route.replace(base_path, '')
            method = route.split(' ')[0].lower()
            route = route.replace(method.upper() + ' ', '')
            for path in swagger_dict['paths']:
                if route == path:
                    if 'parameters' in swagger_dict['paths'][path][method]:
                        if 'requestBody' not in swagger_dict['paths'][path][method]:
                            return swagger_dict['paths'][path][method]['parameters']
                    return swagger_dict['paths'][path][method]
            return None
        except KeyError as e:
            logging.warning("[-] Skipping " + route + " : " + str(e))
            return None

    # transform dict {array: something} and if something is a dict and contains {array: something} transform it
    def _transform_array(self, array: dict) -> list:
        if 'array' in array:
            if isinstance(array['array'], dict):
                array = [self._transform_array(array['array'])]
            else:
                array = [self.AUTOFILL_VALUES[array['array']]]
        else:
            for key in array:
                if isinstance(array[key], dict):
                    array[key] = self._transform_array(array[key])
                elif 'array' in array[key]:
                    array[key] = [self.AUTOFILL_VALUES[array[key]['array']]]
                else:
                    array[key] = self.AUTOFILL_VALUES[array[key]]
        return array

    def _transform_query(self, route: str, param: dict, option: str):
        if '?' in self.routes[route][0]['route'] or '?' in option:
            option += "&" + param['name'] + "="
        else:
            option += "?" + param['name'] + "="
        if "type" in param:
            if 'enum' in param['type']:
                option += param['type']['enum'][0]
            elif 'array' in param['type']:
                option += self.AUTOFILL_VALUES[param['type']['array']]
            else:
                if isinstance(self.AUTOFILL_VALUES[param['type']], bool):
                    option += str(self.AUTOFILL_VALUES[param['type']])
                else:
                    option += self.AUTOFILL_VALUES[param['type']]
        elif "in" in param:
            if param['in'] == "query":
                if self.swagger_dict['basePath']:
                    route_parsed = route.split(self.swagger_dict['basePath'])[1]
                elif self.swagger_dict['host']:
                    route_parsed = route.split(self.swagger_dict['host'])[1]
                else:
                    # we will use the target url from -u option
                    pass
                method = route.split(' ')[0].lower()
                param = self.swagger_dict['paths'][route_parsed][method]['parameters'][0]['schema']
                if not 'type' in param:
                    param['type'] = "string"
                if 'enum' in param:
                    option += param['enum'][0]
                elif 'array' in param:
                    option += self.AUTOFILL_VALUES[param['array']]
                else:
                    if 'array' in param['type']:
                        option += self.AUTOFILL_VALUES[param['items']['type']]
                    else:
                        option += self.AUTOFILL_VALUES[param['type']]

        return option

    def _transform_url(self, param: dict, url: str, route: str) -> str:
        name = param['name']
        if "{" in url:
            if self.swagger_dict['basePath']:
                route_parsed = route.split(self.swagger_dict['basePath'])[1]
            elif self.swagger_dict['host']:
                route_parsed = route.split(self.swagger_dict['host'])[1]
            else:
                # we will use the target url from -u option
                pass
            method = route.split(' ')[0].lower()
            if 'type' not in param:
                param = self.swagger_dict['paths'][route_parsed][method]['parameters'][0]['schema']
                if 'type' not in param:
                    # if still missing, we add a default type string
                    param['type'] = "string"
        return url.replace("{" + name + "}", self.AUTOFILL_VALUES[param['type']])

    def _transform_body(self, param: dict) -> str:
        json_dict = {}
        if param['model']:
            for key in param['model']:
                if 'array' in param['model'][key]:
                    json_dict[key] = self._transform_array(param['model'][key])
                elif isinstance(param['model'][key], dict):
                    json_dict[key] = self._replace_param(param['model'][key])
                else:
                    json_dict[key] = self.AUTOFILL_VALUES[param['model'][key]]
        return json.dumps(json_dict)

    def _transform_formData(self, param: dict, files: list) -> str:
        data = ""
        if 'type' in param:
            if 'enum' in param['type']:
                data = self._add_data(data, param['name'], param['type']['enum'][0])
            elif 'array' in param['type']:
                data = self._add_data(data, param['name'], "[" + self.AUTOFILL_VALUES[param['type']['array']] + "]")
            else:
                if param['type'] == "file":
                    files.append([param['name'], self.AUTOFILL_VALUES[param['type']]])
                else:
                    data = self._add_data(data, param['name'], self.AUTOFILL_VALUES[param['type']])
        return data

    # create request with default value from swagger file
    def _create_request(self, routes: dict) -> list[Request]:
        requests_list = []
        for route, urls in routes.items():
            if not urls:
                continue
            url = urls[0]['route']
            data = ""
            header = {}
            option = ""
            files = []
            if 'params' in urls[0]:
                for param in urls[0]['params']:
                    if 'in' in param:
                        if param['in'] == "path":
                            url = self._transform_url(param, url, route)
                            if 'model' in param:
                                data = self._transform_body(param)
                        elif param['in'] == "query":
                            option = self._transform_query(route, param, option)
                        elif param['in'] == "body" and 'model' in param:
                            data = self._transform_body(param)
                        elif param['in'] == "formData":
                            data = self._transform_formData(param, files)
                        elif param['in'] == "header":
                            if not 'type' in param:
                                param["type"] = "string"
                            header[param['name']] = self.AUTOFILL_VALUES[param['type']]
            request = Request(path=url + option, method=urls[0]['method'], post_params=data, file_params=files,
                              enctype="application/json")
            request.set_headers(header)
            requests_list.append(request)
        return requests_list

    @staticmethod
    def _add_data(data, name: str, value: str) -> str:
        if data != "":
            data += "&" + name + "=" + value
        else:
            data += name + "=" + value
        return data

    def _replace_param(self, json_dict: dict) -> dict:
        if 'array' in json_dict:
            if isinstance(json_dict['array'], dict):
                json_dict = [self._replace_param(json_dict['array'])]
            else:
                json_dict = [self.AUTOFILL_VALUES[json_dict['array']]]
        else:
            for key in json_dict:
                if isinstance(json_dict[key], dict):
                    self._replace_param(json_dict[key])
                elif 'array' in json_dict[key]:
                    json_dict[key] = [self.AUTOFILL_VALUES[json_dict[key]['array']]]
                else:
                    try:
                        json_dict[key] = self.AUTOFILL_VALUES[json_dict[key]]
                    except TypeError as e:
                        logging.warning("[-] Warning: Unexpected type for AUTOFILL_VALUES key," +
                                        " probably due to unsupported format: " + str(e))
        return json_dict

    def get_requests(self) -> list[Request]:
        if self.routes:
            return self._create_request(self.routes)
        return []
