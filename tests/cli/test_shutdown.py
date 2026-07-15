import sys
from unittest import mock

import asyncio
import pytest

from wapitiCore.main.wapiti import _shutdown, wapiti_asyncio_wrapper


class TestShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_no_pending_tasks(self):
        loop = asyncio.get_running_loop()
        await _shutdown(loop, timeout=1.0)

    @pytest.mark.asyncio
    async def test_shutdown_pending_tasks_are_cancelled(self):
        loop = asyncio.get_running_loop()

        async def never_finish():
            while True:
                await asyncio.sleep(3600)

        task = asyncio.create_task(never_finish())
        await asyncio.sleep(0)
        assert not task.cancelled()

        await _shutdown(loop, timeout=0.5)
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_shutdown_hanging_task_times_out(self):
        loop = asyncio.get_running_loop()

        hang = asyncio.Event()

        async def hanging_task():
            await hang.wait()

        task = asyncio.create_task(hanging_task())
        await asyncio.sleep(0)
        assert not task.done()

        await _shutdown(loop, timeout=0.1)
        assert task.cancelled()


class TestMonkeyPatch:
    def test_patch_applied_when_sqlalchemy_available(self):
        from wapitiCore.main.wapiti import _timed_terminate_graceful_close
        import sqlalchemy.dialects.sqlite.aiosqlite as sa_aiosqlite
        assert sa_aiosqlite.AsyncAdapt_terminate._terminate_graceful_close is _timed_terminate_graceful_close

    @pytest.mark.asyncio
    async def test_timed_terminate_calls_original(self):
        from wapitiCore.main.wapiti import _timed_terminate_graceful_close, _ORIGINAL_TERMINATE
        original = _ORIGINAL_TERMINATE

        async def dummy_original(_self):
            pass

        with mock.patch("wapitiCore.main.wapiti._ORIGINAL_TERMINATE", dummy_original):
            mock_self = mock.AsyncMock()
            await _timed_terminate_graceful_close(mock_self)

    @pytest.mark.asyncio
    async def test_timed_terminate_timeout_does_not_raise(self):
        from wapitiCore.main.wapiti import _timed_terminate_graceful_close

        async def hanging(_self):
            await asyncio.Event().wait()

        with mock.patch("wapitiCore.main.wapiti._ORIGINAL_TERMINATE", hanging):
            mock_self = mock.AsyncMock()
            await _timed_terminate_graceful_close(mock_self)
