#!/usr/bin/env python3
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

VERSION = "3.0.2"
DOC_DIR = "share/doc/wapiti"


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        try:
            from multiprocessing import cpu_count
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
            "doc/COPYING",
            "doc/example.txt",
            "doc/FAQ.md",
            "doc/wapiti.1.html",
            "doc/wapiti.ronn",
            "doc/wapiti-getcookie.1.html",
            "doc/wapiti-getcookie.ronn",
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

parser_name = "lxml"

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
    url="http://wapiti.sourceforge.net/",
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
        "requests",
        "beautifulsoup4",
        parser_name,
        "tld",
        "yaswfp",
        "mako",
        "PySocks"
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
    tests_require=["pytest", "responses"],
    setup_requires=["pytest-runner"],
    cmdclass={"test": PyTest}
)
