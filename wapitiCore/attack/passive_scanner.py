from importlib import import_module
import inspect
from pathlib import Path
from typing import Dict, Generator, List, Tuple, Any, Optional
from xml.etree import ElementTree

from wapitiCore.attack.active_scanner import module_to_class_name
from wapitiCore.attack.attack import Attack
from wapitiCore.attack.modules.core import ModuleActivationSettings
from wapitiCore.main.log import logging
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.net.sql_persister import SqlPersister


class PassiveScanContext:
    def __init__(self, request: Request, response: Response):
        self.request = request
        self.response = response
        self.media_type = (self.response.type.split(";", 1)[0].strip().lower() if self.response.type else "")

        self._html = None
        self._html_loaded = False
        self._json = None
        self._json_loaded = False
        self._xml = None
        self._xml_loaded = False

    @property
    def has_content(self) -> bool:
        return bool(self.response.content)

    def is_html(self) -> bool:
        return self.media_type in {"text/html", "application/xhtml+xml"}

    def is_json(self) -> bool:
        return self.media_type == "application/json" or self.media_type.endswith("+json")

    def is_xml(self) -> bool:
        return self.media_type in {"application/xml", "text/xml"} or self.media_type.endswith("+xml")

    def is_text(self) -> bool:
        return self.media_type.startswith("text/")

    def is_document_like(self) -> bool:
        return self.is_html() or self.is_json() or self.is_xml() or self.is_text()

    def get_html(self):
        if self._html_loaded:
            return self._html

        self._html_loaded = True
        if not self.is_html() or not self.has_content:
            return None

        from wapitiCore.parsers.html_parser import Html
        self._html = Html(self.response.content, self.request.url)
        return self._html

    def get_json(self):
        if self._json_loaded:
            return self._json

        self._json_loaded = True
        if not self.is_json() or not self.has_content:
            return None

        self._json = self.response.json
        return self._json

    def get_xml(self) -> Optional[ElementTree.Element]:
        if self._xml_loaded:
            return self._xml

        self._xml_loaded = True
        if not self.is_xml() or not self.has_content:
            return None

        try:
            self._xml = ElementTree.fromstring(self.response.content)
        except ElementTree.ParseError:
            self._xml = None

        return self._xml


class PassiveScanner:
    def __init__(self, persister: SqlPersister):
        self._persister = persister
        self._modules: Dict[str, Attack] = {}
        self._module_supports_context: Dict[str, bool] = {}
        self._activated_modules: ModuleActivationSettings = {}
        self._active_modules: List[Tuple[str, Attack]] = []
        self._load_modules()

    def _load_modules(self):
        passive_modules_dir = Path(__file__).parent / "modules" / "passive"

        for module_file_name in passive_modules_dir.glob("mod_*.py"):
            mod_name = module_file_name.stem
            try:
                try:
                    mod = import_module("wapitiCore.attack.modules.passive." + mod_name)
                except ImportError as error:
                    logging.error("[!] Unable to import module %s: %s", mod_name, error)
                    continue

                class_name = module_to_class_name(mod_name)
                class_instance = getattr(mod, class_name)(
                )
                self._module_supports_context[class_instance.name] = (
                    "context" in inspect.signature(class_instance.analyze).parameters
                )
            except Exception:  # pylint: disable=broad-except
                # Catch every possible exception and print it
                logging.exception("[!] Module %s seems broken and will be skipped", mod_name)
                continue

            self._modules[class_instance.name] = class_instance

    def set_modules(self, module_options: ModuleActivationSettings):
        self._activated_modules = module_options
        self._active_modules = [
            (module_name, module_instance)
            for module_name, module_instance in self._modules.items()
            if module_name in module_options
        ]

    def _iter_vulnerabilities(
            self,
            module_name: str,
            module_instance: Attack,
            request: Request,
            response: Response,
            context: PassiveScanContext
    ) -> Generator[VulnerabilityInstance, Any, None]:
        if self._module_supports_context.get(module_name, False):
            yield from module_instance.analyze(request, response, context=context)
            return
        yield from module_instance.analyze(request, response)

    async def scan(self, request: Request, response: Response):
        context = PassiveScanContext(request, response)
        for passive_module_name, passive_module_instance in self._active_modules:
            for vulnerability in self._iter_vulnerabilities(
                    passive_module_name,
                    passive_module_instance,
                    request,
                    response,
                    context
            ):
                await self._record_vulnerability_instance(vulnerability, passive_module_name)

    async def _record_vulnerability_instance(self, vuln_instance: VulnerabilityInstance, module: str):
        await self._persister.add_payload(
            payload_type=vuln_instance.finding_class.type(),
            module=module,
            category=vuln_instance.finding_class.name(),
            level=vuln_instance.severity,
            request=vuln_instance.request,
            parameter=vuln_instance.parameter,
            info=vuln_instance.info,
            wstg=vuln_instance.finding_class.wstg_code(),
            response=vuln_instance.response
        )
