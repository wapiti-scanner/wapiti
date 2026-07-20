from collections import defaultdict
from importlib import import_module
from pathlib import Path
from typing import Dict

from wapitiCore.attack.active_scanner import module_to_class_name
from wapitiCore.attack.attack import Attack
from wapitiCore.attack.modules.core import ModuleActivationSettings
from wapitiCore.main.log import log_blue, logging
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
                    logging.error("[!] Unable to import module %s: %s", mod_name, error)
                    continue

                class_name = module_to_class_name(mod_name)
                class_instance = getattr(mod, class_name)(
                )
            except Exception:  # pylint: disable=broad-except
                # Catch every possible exception and print it
                logging.exception("[!] Module %s seems broken and will be skipped", mod_name)
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

    def log_summary(self):
        """Log, once at the end of the crawl, how many alerts each module suppressed.

        Passive modules cap the number of alerts they emit per deduplication key
        to avoid flooding the report (see ``PassiveModule.should_report``). This
        reports the volume that was silently dropped, mirroring the way the active
        scanner surfaces its ``network_errors`` counter.
        """
        suppressed_by_module = {
            module_name: getattr(module_instance, "suppressed_findings", 0)
            for module_name, module_instance in self._modules.items()
        }
        suppressed_by_module = {
            module_name: count for module_name, count in suppressed_by_module.items() if count
        }
        if not suppressed_by_module:
            return

        log_blue("")
        log_blue("[*] Some similar passive alerts were suppressed to keep the report readable:")
        for module_name, suppressed in suppressed_by_module.items():
            log_blue("    {0}: {1} similar alert(s) suppressed", module_name, suppressed)

    def suppressed_by_category(self) -> Dict[str, int]:
        """Total number of suppressed alerts, broken down per vulnerability category.

        Aggregates every module's ``suppressed_by_category`` counter. The report
        is organized per category (finding class), not per module, so this is the
        breakdown a report needs to annotate the right summary line and section.
        """
        totals: Dict[str, int] = defaultdict(int)
        for module_instance in self._modules.values():
            for category, count in getattr(module_instance, "suppressed_by_category", {}).items():
                totals[category] += count
        return dict(totals)

    async def persist_suppressed_findings(self):
        """Store the per-category suppression counts so the report survives the crawl.

        The report is generated in a later, possibly decoupled step (e.g. a resumed
        scan with ``--skip-crawl``, or regenerating a report from the ``.db`` file),
        when the in-memory module counters are gone. Persisting them keeps the
        information available to every report format.
        """
        counts = self.suppressed_by_category()
        if counts:
            await self._persister.set_suppressed_findings(counts)

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
