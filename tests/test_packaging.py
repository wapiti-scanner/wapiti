import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not (ROOT / "pyproject.toml").is_file(), reason="needs the source tree")
def test_package_discovery():
    """The wheel must ship every wapitiCore sub-package and no other top-level directory such as doc/ (#699)"""
    setuptools = pytest.importorskip("setuptools")
    with open(ROOT / "pyproject.toml", "rb") as fd:
        find_options = tomllib.load(fd)["tool"]["setuptools"]["packages"]["find"]

    packages = set(setuptools.find_namespace_packages(str(ROOT), **find_options))
    sub_packages = {".".join(path.parent.relative_to(ROOT).parts) for path in (ROOT / "wapitiCore").rglob("*.py")}

    assert sub_packages <= packages
    assert {package.split(".")[0] for package in packages} == {"wapitiCore"}
