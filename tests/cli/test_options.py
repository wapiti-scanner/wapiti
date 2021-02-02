from wapitiCore.main.wapiti import Wapiti
from wapitiCore.attack.attack import commons, modules


def test_options():
    cli = Wapiti("http://perdu.com/", session_dir="/dev/shm")
    cli.set_attack_options({"timeout": 10})

    cli.set_modules("-all,xxe")
    cli._init_attacks()
    assert {module.name for module in cli.attacks if module.do_get or module.do_post} == {"xxe"}

    cli.set_modules("xxe")
    cli._init_attacks()
    assert {module.name for module in cli.attacks if module.do_get or module.do_post} == {"xxe"}

    cli.set_modules("common,xxe")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert len(activated_modules) == len(commons) + 1

    cli.set_modules("common,-exec")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert len(activated_modules) == len(commons) - 1

    cli.set_modules("all,-xxe")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert len(activated_modules) == len(modules) - 1

    cli.set_modules("all,-common")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert len(activated_modules) == len(modules) - len(commons)

    cli.set_modules("common,-all,xss")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert len(activated_modules) == 1

    # Empty module list: no modules will be used
    cli.set_modules("")
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert not activated_modules

    # Use default settings: only use "commons" modules
    cli.set_modules(None)
    cli._init_attacks()
    activated_modules = {module.name for module in cli.attacks if module.do_get or module.do_post}
    assert activated_modules == set(commons)
