import time
from unittest import mock

from wapitiCore.main import wapiti as wapiti_main_module


class TestShutdownWatchdog:
    def test_force_process_exit_calls_os_exit_zero(self):
        # The watchdog must exit with status 0 after flushing the standard streams.
        with mock.patch.object(wapiti_main_module.os, "_exit") as os_exit, \
                mock.patch.object(wapiti_main_module.sys.stdout, "flush") as out_flush, \
                mock.patch.object(wapiti_main_module.sys.stderr, "flush") as err_flush:
            wapiti_main_module._force_process_exit()  # pylint: disable=protected-access

        out_flush.assert_called_once()
        err_flush.assert_called_once()
        os_exit.assert_called_once_with(0)

    def test_watchdog_is_disarmed_on_clean_shutdown(self):
        # A shutdown that finishes quickly must cancel the watchdog before it can
        # fire, so the process exits normally (no os._exit).
        created = {}
        real_timer = wapiti_main_module.threading.Timer

        def fake_timer(interval, func):
            timer = real_timer(interval, func)
            created["timer"] = timer
            created["cancel"] = mock.Mock(wraps=timer.cancel)
            timer.cancel = created["cancel"]
            return timer

        async def fast_main():
            return None

        with mock.patch.object(wapiti_main_module.threading, "Timer", side_effect=fake_timer), \
                mock.patch.object(wapiti_main_module, "wapiti_main", fast_main), \
                mock.patch.object(wapiti_main_module.os, "_exit") as os_exit:
            wapiti_main_module.wapiti_asyncio_wrapper()

        os_exit.assert_not_called()
        created["cancel"].assert_called()

    def test_watchdog_fires_when_shutdown_hangs(self):
        # If the event loop teardown never returns, the watchdog must force the
        # process out. We shorten the timeout and simulate a hanging teardown.
        async def hanging_main():
            return None

        fired = {"exit": False}

        def fake_exit(_code):
            fired["exit"] = True

        # A Runner whose close() blocks forever mimics the aiosqlite deadlock.
        class HangingRunner:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                # Block until the watchdog fires, then let the test proceed.
                deadline = time.monotonic() + 5.0
                while not fired["exit"] and time.monotonic() < deadline:
                    time.sleep(0.01)

            def run(self, _coro):
                _coro.close()

        with mock.patch.object(wapiti_main_module, "SHUTDOWN_WATCHDOG_TIMEOUT", 0.2), \
                mock.patch.object(wapiti_main_module.asyncio, "Runner", HangingRunner), \
                mock.patch.object(wapiti_main_module, "wapiti_main", hanging_main), \
                mock.patch.object(wapiti_main_module.os, "_exit", side_effect=fake_exit):
            wapiti_main_module.wapiti_asyncio_wrapper()

        assert fired["exit"] is True
