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


class _FindingA:
    @staticmethod
    def name():
        return "Category A"


class _FindingB:
    @staticmethod
    def name():
        return "Category B"


def test_suppressions_are_tallied_per_finding_category():
    module = PassiveModule()

    # First occurrence of each key is reported, subsequent ones are suppressed
    # and counted against the finding class category.
    assert module.should_report("a", _FindingA) is True
    assert module.should_report("a", _FindingA) is False
    assert module.should_report("a", _FindingA) is False
    assert module.should_report("b", _FindingB) is True
    assert module.should_report("b", _FindingB) is False

    assert module.suppressed_findings == 3
    assert dict(module.suppressed_by_category) == {"Category A": 2, "Category B": 1}


def test_suppressions_without_category_only_bump_the_total():
    module = PassiveModule()

    assert module.should_report("k") is True
    assert module.should_report("k") is False

    assert module.suppressed_findings == 1
    assert dict(module.suppressed_by_category) == {}
