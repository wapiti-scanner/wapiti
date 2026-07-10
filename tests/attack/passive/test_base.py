from wapitiCore.attack.modules.passive.base import PassiveModule


def test_should_report_defaults_to_report_once_per_key():
    module = PassiveModule()

    assert module.should_report(("host", "type")) is True
    # Same key again is suppressed with the default LIMIT of 1
    assert module.should_report(("host", "type")) is False
    assert module.should_report(("host", "type")) is False
    # A different key is reported independently
    assert module.should_report(("host", "other")) is True

    assert module.suppressed_findings == 2


def test_limit_allows_several_occurrences_before_suppressing():
    module = PassiveModule()
    module.LIMIT = 2

    assert module.should_report("k") is True
    assert module.should_report("k") is True
    assert module.should_report("k") is False

    assert module.suppressed_findings == 1
