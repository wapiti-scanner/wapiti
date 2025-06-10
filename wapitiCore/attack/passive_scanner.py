from importlib import import_module
from pathlib import Path
from typing import Dict

from wapitiCore.attack.active_scanner import module_to_class_name
from wapitiCore.attack.attack import Attack
from wapitiCore.attack.modules.core import ModuleActivationSettings
from wapitiCore.main.log import logging
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.net.sql_persister import SqlPersister


class PassiveScanner:
    def __init__(self, persister: SqlPersister):
        self._persister = persister
        self._modules: Dict[str, Attack] = {}
        self._activated_modules: ModuleActivationSettings = {}
        self._load_modules()

    def _load_modules(self):
        passive_modules_dir = Path(__file__).parent / "modules" / "passive"

        for module_file_name in passive_modules_dir.glob("mod_*.py"):
            mod_name = module_file_name.stem
            try:
                try:
                    mod = import_module("wapitiCore.attack.modules.passive." + mod_name)
                except ImportError as error:
                    logging.error(f"[!] Unable to import module {mod_name}: {error}")
                    continue

                class_name = module_to_class_name(mod_name)
                class_instance = getattr(mod, class_name)(
                )
            except Exception as exception:  # pylint: disable=broad-except
                # Catch every possible exceptions and print it
                logging.error(f"[!] Module {mod_name} seems broken and will be skipped")
                logging.exception(exception.__class__.__name__, exception)
                continue

            self._modules[class_instance.name] = class_instance

    def set_modules(self, module_options: ModuleActivationSettings):
        self._activated_modules = module_options

    async def scan(self, request: Request, response: Response):
        for passive_module_name, passive_module_instance in self._modules.items():
            if passive_module_instance.name not in self._activated_modules:
                continue

            for vulnerability in passive_module_instance.analyze(request, response):
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
