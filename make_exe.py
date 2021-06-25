#!/usr/bin/env python3
# Don't use this script unless you know exactly what you are doing !
from distutils.core import setup
import py2exe
import os
import sys

# dirty hack so we don't have to give any argument
if "py2exe" not in sys.argv:
    sys.argv.append("py2exe")

VERSION = "3.0.5"


# Build file lists
def build_file_list(results, dest, root, src=""):
    cwd = os.getcwd()
    if src != "":
        os.chdir(src)
    for root, dirs, files in os.walk(root):
        if ".svn" in dirs:
            dirs.remove(".svn")
        if files:
            results.append((os.path.join(dest, root), [os.path.join(src, root, x) for x in files]))
    os.chdir(cwd)


data_files = [
    ("data", ["INSTALL", "README", "TODO", "VERSION"])
]

build_file_list(data_files, "data", "doc", src="")
build_file_list(data_files, "data", "data", src="wapitiCore")
build_file_list(data_files, "data", "report_template", src="wapitiCore")
build_file_list(data_files, "data", "language_sources", src="wapitiCore")


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
    author="Nicolas SURRIBAS",
    author_email="nicolas.surribas@gmail.com",
    license="GPLv2",
    platforms=["Any"],
    packages=[
        'wapitiCore',
        'wapitiCore.attack',
        'wapitiCore.language',
        'wapitiCore.report',
        'wapitiCore.net',
        'wapitiCore.file',
        'wapitiCore.net.jsparser'
    ],
    data_files=data_files,
    console=[
        {
            "script": "bin/wapiti",
            "icon_resources": [(1, "doc/wapiti.ico")]
        },
        {
            "script": "bin/wapiti-cookie",
            "icon_resources": [(1, "doc/cookie.ico")]
        },
        {
            "script": "bin/wapiti-getcookie",
            "icon_resources": [(1, "doc/cookie.ico")]
        }
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Software Development :: Testing'
    ],
    options={
        "py2exe": {
            "includes": [
                "wapitiCore.attack.mod_backup",
                "wapitiCore.attack.mod_brute_login_form",
                "wapitiCore.attack.mod_timesql",
                "wapitiCore.attack.mod_buster",
                "wapitiCore.attack.mod_cookieflags",
                "wapitiCore.attack.mod_crlf",
                "wapitiCore.attack.mod_csp",
                "wapitiCore.attack.mod_drupal_enum",
                "wapitiCore.attack.mod_exec",
                "wapitiCore.attack.mod_file",
                "wapitiCore.attack.mod_htaccess",
                "wapitiCore.attack.mod_http_headers",
                "wapitiCore.attack.mod_methods",
                "wapitiCore.attack.mod_nikto",
                "wapitiCore.attack.mod_permanentxss",
                "wapitiCore.attack.mod_http_post",
                "wapitiCore.attack.mod_redirect",
                "wapitiCore.attack.mod_shellshock",
                "wapitiCore.attack.mod_sql",
                "wapitiCore.attack.mod_ssrf",
                "wapitiCore.attack.mod_xss",
                "wapitiCore.attack.mod_xxe",
                "wapitiCore.attack.mod_wp_enum",
                "wapitiCore.report.reportgenerator",
                "wapitiCore.report.htmlreportgenerator",
                "wapitiCore.report.jsonreportgenerator",
                "wapitiCore.report.txtreportgenerator",
                "wapitiCore.report.xmlreportgenerator"
            ]
        }
    }
)
