from asyncio import Event
from unittest import mock

import pytest
from wapitiCore.attack.attack import commons, modules, passives
from wapitiCore.main.wapiti import Wapiti


@pytest.mark.asyncio
async def test_options():

    class CustomMock():

        CONFIG_DIR = ""

        def __init__(self):
            pass

        async def count_paths(self):
            return 0

    with mock.patch("os.makedirs", return_value=True):
        stop_event = Event()
        cli = Wapiti("http://perdu.com/", session_dir="/dev/shm")
        cli.persister = CustomMock()
        cli.set_attack_options({"timeout": 10})

        cli.set_modules("-all,xxe")
        await cli._init_attacks(stop_event)
        assert {module.name for module in cli.attacks if module.do_get or module.do_post} == {"xxe"}

        cli.set_modules("xxe")
        await cli._init_attacks(stop_event)
        assert {module.name for module in cli.attacks if module.do_get or module.do_post} == {"xxe"}

        cli.set_modules("common,xxe")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(commons) + 1

        cli.set_modules("common,-exec")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(commons) - 1

        cli.set_modules("all,-xxe")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(modules) - 1

        cli.set_modules("all,-common")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(modules) - len(commons)

        cli.set_modules("common,-all,xss")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == 1

        cli.set_modules("passive")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(passives)

        cli.set_modules("passive,xxe")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(passives) + 1

        cli.set_modules("passive,-wapp")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert len(activated_modules) == len(passives) - 1

        # Empty module list: no modules will be used
        cli.set_modules("")
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert not activated_modules

        # Use default settings: only use "commons" modules
        cli.set_modules(None)
        await cli._init_attacks(stop_event)
        activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
        assert activated_modules == set(commons)
