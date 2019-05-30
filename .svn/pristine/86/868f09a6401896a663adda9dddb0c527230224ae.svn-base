#!/usr/bin/env python3
from setuptools import setup, find_packages

VERSION = "3.0.1"
DOC_DIR = "share/doc/wapiti"

doc_and_conf_files = [
    (
        DOC_DIR,
        [
            "doc/AUTHORS",
            "doc/ChangeLog_Wapiti",
            "doc/ChangeLog_lswww",
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

parser_name = "html5lib"

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
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Software Development :: Testing'
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
        'NTLM': ["requests_ntlm"],
        'Kerberos': ["requests_kerberos"],
    },
    entry_points={
        "console_scripts": [
            "wapiti = wapitiCore.main.wapiti:wapiti_main",
            "wapiti-getcookie = wapitiCore.main.getcookie:getcookie_main",
        ],
    }
)
