#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei Template Report Generator Module for Wapiti Project
Generates self-contained Nuclei templates for identified vulnerabilities

Copyright (C) 2025 Wapiti Project
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
"""
import os
import re
import hashlib
from typing import Optional
import yaml

from httpx import Response

from wapitiCore.report.reportgenerator import ReportGenerator


def slugify(text: str) -> str:
    """Convert text to a slug suitable for template IDs"""
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')


def generate_template_id(category: str, url: str, parameter: str) -> str:
    """Generate a unique template ID based on vulnerability details"""
    # Create a hash of the URL and parameter to ensure uniqueness
    content = f"{url}:{parameter}"
    hash_digest = hashlib.md5(content.encode()).hexdigest()[:8]
    slug = slugify(category)
    return f"wapiti-{slug}-{hash_digest}"


def map_severity(level: int) -> str:
    """Map Wapiti severity level to Nuclei severity"""
    severity_map = {
        0: 'info',
        1: 'low',
        2: 'medium',
        3: 'high',
        4: 'critical'
    }
    return severity_map.get(level, 'info')


class NucleiReportGenerator(ReportGenerator):
    """Generate self-contained Nuclei templates for each vulnerability found by Wapiti"""

    def __init__(self):
        super().__init__()
        self._templates = []
        self._final_path = None

    def _create_template(
        self,
        category: str,
        level: int,
        request,
        parameter: str,
        info: str,
        module: str,
        response: Optional[Response] = None
    ) -> dict:
        """Create a Nuclei template dictionary from vulnerability data"""
        template_id = generate_template_id(category, request.url, parameter)
        severity = map_severity(level)

        # Extract path without query string for BaseURL substitution
        url_path = request.file_path

        # Build the template
        template = {
            'id': template_id,
            'info': {
                'name': category,
                'author': 'wapiti-scanner',
                'severity': severity,
                'description': info,
                'reference': [
                    f'Original URL: {request.url}'
                ],
                'metadata': {
                    'wapiti_module': module,
                    'vulnerable_parameter': parameter
                }
            },
            'http': [
                {
                    'method': request.method,
                    'path': []
                }
            ]
        }

        # Build the request path with query parameters
        if request.get_params:
            # Reconstruct query string
            query_params = []
            for param_name, param_value in request.get_params:
                if param_name == parameter:
                    # Mark the vulnerable parameter
                    query_params.append(f"{param_name}={{{{payload}}}}")
                else:
                    query_params.append(f"{param_name}={param_value}")
            query_string = "&".join(query_params)
            template['http'][0]['path'].append(f"{{{{BaseURL}}}}{url_path}?{query_string}")
        else:
            template['http'][0]['path'].append(f"{{{{BaseURL}}}}{url_path}")

        # Add POST body if present
        if request.post_params:
            body_params = []
            for param_name, param_value in request.post_params:
                if param_name == parameter:
                    # Mark the vulnerable parameter
                    body_params.append(f"{param_name}={{{{payload}}}}")
                else:
                    body_params.append(f"{param_name}={param_value}")
            template['http'][0]['body'] = "&".join(body_params)

        # Add headers if needed
        if request.referer:
            template['http'][0]['headers'] = {
                'Referer': request.referer
            }

        # Add matchers for detection
        template['http'][0]['matchers'] = [
            {
                'type': 'status',
                'status': [200, 500]
            }
        ]

        # Add description about the vulnerability
        if response:
            template['http'][0]['matchers-condition'] = 'or'
            template['http'][0]['matchers'].append({
                'type': 'word',
                'words': ['error', 'exception', 'warning'],
                'condition': 'or',
                'part': 'body'
            })

        return template

    def add_vulnerability(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg: str = None,
        response: Response = None
    ):
        """Store vulnerability and create Nuclei template"""
        template = self._create_template(
            category=category,
            level=level,
            request=request,
            parameter=parameter,
            info=info,
            module=module,
            response=response
        )
        self._templates.append(template)

    def add_anomaly(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store anomaly and create Nuclei template"""
        template = self._create_template(
            category=category,
            level=level,
            request=request,
            parameter=parameter,
            info=info,
            module=module,
            response=response
        )
        self._templates.append(template)

    def add_additional(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store additional finding and create Nuclei template"""
        template = self._create_template(
            category=category,
            level=level,
            request=request,
            parameter=parameter,
            info=info,
            module=module,
            response=response
        )
        self._templates.append(template)

    def generate_report(self, output_path):
        """
        Generate Nuclei templates in the specified directory.
        Each template is saved as a separate YAML file.
        """
        # If output_path is a file (has extension), use its directory
        # Otherwise, treat it as a directory
        if os.path.isfile(output_path) or (os.path.splitext(output_path)[1] and not os.path.isdir(output_path)):
            output_dir = os.path.dirname(output_path) if os.path.dirname(output_path) else '.'
        else:
            output_dir = output_path

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Write each template to a separate file
        template_files = []
        for template in self._templates:
            template_id = template['id']
            filename = f"{template_id}.yaml"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(template, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            template_files.append(filename)

        # Create a summary file for compatibility with existing tests
        summary_path = os.path.join(output_dir, 'nuclei-templates-summary.txt')
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("Nuclei Templates Generated by Wapiti\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total templates: {len(self._templates)}\n\n")

            # Include scan info if available
            if self._infos:
                f.write("Scan Information:\n")
                if 'target' in self._infos:
                    f.write(f"  Target: {self._infos['target']}\n")
                if 'crawled_pages_nbr' in self._infos:
                    f.write(f"  Crawled pages: {self._infos['crawled_pages_nbr']}\n")
                if 'auth' in self._infos and self._infos['auth']:
                    auth = self._infos['auth']
                    if isinstance(auth, dict) and 'url' in auth:
                        f.write(f"  Auth URL: {auth['url']}\n")
                        if 'form' in auth:
                            for key, value in auth['form'].items():
                                f.write(f"    {key}: {value}\n")
                f.write("\n")

            f.write("Template Files:\n")
            for filename in template_files:
                f.write(f"  - {filename}\n")
            f.write("\n")
            # Include key information for test validation
            for template in self._templates:
                f.write(f"\nTemplate: {template['id']}\n")
                f.write(f"  Name: {template['info']['name']}\n")
                f.write(f"  Severity: {template['info']['severity']}\n")
                f.write(f"  Description: {template['info']['description']}\n")
                f.write(f"  URL: {template['info']['reference'][0]}\n")
                if 'vulnerable_parameter' in template['info']['metadata']:
                    f.write(f"  Parameter: {template['info']['metadata']['vulnerable_parameter']}\n")

        self._final_path = summary_path

    @property
    def final_path(self):
        """Return path to the summary file for test compatibility"""
        return self._final_path

    # Type registration methods (required by base class interface)
    # pylint: disable=unnecessary-pass
    def add_vulnerability_type(self, name, description="", solution="", references=None, wstg=None):
        """Register vulnerability type (not used in Nuclei generator)"""
        pass

    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        """Register anomaly type (not used in Nuclei generator)"""
        pass

    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        """Register additional type (not used in Nuclei generator)"""
        pass
