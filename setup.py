#!/usr/bin/env python3
import sys
from multiprocessing import cpu_count

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

VERSION = "3.0.4"
DOC_DIR = "share/doc/wapiti"


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        try:
            self.pytest_args = ["-n", str(cpu_count()), "--boxed"]
        except (ImportError, NotImplementedError):
            self.pytest_args = ["-n", "1", "--boxed"]

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


doc_and_conf_files = [
    (
        DOC_DIR,
        [
            "doc/AUTHORS",
            "doc/ChangeLog_Wapiti",
            "doc/ChangeLog_lswww",
            "doc/endpoints.md",
            "doc/example.txt",
            "doc/FAQ.md",
            "doc/wapiti.1.html",
            "doc/wapiti.ronn",
            "doc/wapiti-getcookie.1.html",
            "doc/wapiti-getcookie.ronn",
            "doc/xxe_module.md",
            "LICENSE",
            "INSTALL.md",
            "README.md",
            "VERSION"
        ]
    ),
    (
        "share/man/man1",
        [
            "doc/wapiti.1",
            "doc/wapiti-getcookie.1"
        ]
    )
]

# parser_name = "html5lib"

# Main
setup(
    name="wapiti3",
    version=VERSION,
    description="A web application vulnerability scanner",
    long_description="""\
Wapiti allows you to audit the security of your web applications.
It performs "black-box" scans, i.e. it does not study the source code of the
application but will scans the webpages of the deployed webapp, looking for
scripts and forms where it can inject data.
Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see
if a script is vulnerable.""",
    url="https://wapiti.sourceforge.io/",
    author="Nicolas Surribas",
    author_email="nicolas.surribas@gmail.com",
    license="GPLv2",
    platforms=["Any"],
    packages=find_packages(),
    data_files=doc_and_conf_files,
    include_package_data=True,
    scripts=[
        "bin/wapiti",
        "bin/wapiti-getcookie"
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: Software Development :: Testing"
    ],
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.3",
        # parser_name,
        "tld>=0.12.2",
        "yaswfp>=0.9.3",
        "mako>=1.1.2",
        "PySocks>=1.7.1",
        "markupsafe==1.1.1",
        "six>=1.15.0",
        "importlib_metadata==2.0.0"
    ],
    extras_require={
        "NTLM": ["requests_ntlm"],
        "Kerberos": ["requests_kerberos"],
    },
    entry_points={
        "console_scripts": [
            "wapiti = wapitiCore.main.wapiti:wapiti_main",
            "wapiti-getcookie = wapitiCore.main.getcookie:getcookie_main",
        ],
    },
    # https://buildmedia.readthedocs.org/media/pdf/pytest/3.6.0/pytest.pdf
    tests_require=["pytest>=6.1.2", "responses==0.12.1"],
    setup_requires=["pytest-runner"],
    cmdclass={"test": PyTest}
)
