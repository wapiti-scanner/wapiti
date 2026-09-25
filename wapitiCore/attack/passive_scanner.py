from importlib import import_module
from pathlib import Path
from typing import Dict, Set

from wapitiCore.attack.active_scanner import module_to_class_name
from wapitiCore.attack.attack import Attack
from wapitiCore.attack.modules.core import ModuleActivationSettings
from wapitiCore.main.log import log_blue, logging
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.net.sql_persister import SqlPersister

# Content types that can't hold a stack trace or a path disclosure: skipped on attack traffic
# before decoding the body.
BINARY_CONTENT_TYPES = ("image/", "audio/", "video/", "font/", "application/octet-stream")


class PassiveScanner:
    def __init__(self, persister: SqlPersister):
        self._persister = persister
        self._modules: Dict[str, Attack] = {}
        self._activated_modules: ModuleActivationSettings = {}
        # Hashes of the attack response bodies already analysed. Payloads often trigger the very
        # same error page, so each distinct body is scanned only once per scan.
        self._seen_attack_bodies: Set[int] = set()
        self._state_restored = False
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

    async def scan_attack_response(self, request: Request, response: Response):
        """Run the body-analysing passive modules on a response produced by an active attack module.

        Only modules flagged with ``scan_attack_responses`` are run: header or redirect based
        checks would just repeat what was already seen during the crawl. Identical bodies are
        analysed once, and findings are recorded on the attack request itself (the persister
        stores it as a new evil request along with its response).
        """
        if response.type.startswith(BINARY_CONTENT_TYPES):
            return

        content = response.content
        if not content:
            return

        digest = hash(content)
        if digest in self._seen_attack_bodies:
            return
        self._seen_attack_bodies.add(digest)

        for passive_module_name, passive_module_instance in self._modules.items():
            if passive_module_instance.name not in self._activated_modules:
                continue

            if not getattr(passive_module_instance, "scan_attack_responses", False):
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

    def get_state(self) -> Dict[str, dict]:
        """Snapshot every module's anti-flood state, keyed by module name."""
        return {
            module_name: module_instance.get_state()
            for module_name, module_instance in self._modules.items()
        }

    def load_state(self, state: Dict[str, dict]):
        """Restore a snapshot produced by :meth:`get_state` into the loaded modules.

        Unknown module names in the snapshot (e.g. a module removed since the
        interrupted run) are ignored so a resume never fails on a stale state.
        """
        for module_name, module_state in state.items():
            module_instance = self._modules.get(module_name)
            if module_instance is not None:
                module_instance.load_state(module_state)

    async def persist_state(self):
        """Store the passive scanner state so both the resume and the report survive the crawl.

        This is the single source of truth for everything the passive scanner
        accumulates: the per-key occurrence counts (so a resumed crawl keeps
        deduplicating instead of re-reporting already-seen alerts) and the
        per-category suppression counters (which the report derives from this same
        state, see ``SqlPersister.get_suppressed_findings``). Written unconditionally
        so the occurrence counts survive even when nothing was suppressed yet.
        """
        await self._persister.set_passive_scanner_state(self.get_state())

    async def restore_state(self):
        """Reload the passive scanner state persisted by a previous (interrupted) crawl.

        Only the first call has an effect: it is made before the crawl and again before the
        attacks (for when the crawl is skipped), and reloading after the crawl would overwrite
        the live in-memory state.
        """
        if self._state_restored:
            return
        self._state_restored = True

        state = await self._persister.get_passive_scanner_state()
        if state:
            self.load_state(state)

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
