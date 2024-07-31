==================================
Wapiti - Web Vulnerability Scanner
==================================

.. image:: https://img.shields.io/pypi/v/wapiti3?label=PyPI&logo=PyPI&logoColor=white&color=blue
    :alt: PyPI version
    :target: https://pypi.python.org/pypi/wapiti3
.. image:: https://img.shields.io/pypi/pyversions/wapiti3
    :alt: Supported Python versions
    :target: https://github.com/wapiti-scanner/wapiti/blob/master/INSTALL.md
.. image:: https://img.shields.io/github/license/wapiti-scanner/wapiti
    :alt: License: GPL-2.0
    :target: https://github.com/wapiti-scanner/wapiti/blob/master/LICENSE
.. image:: https://img.shields.io/pypi/dd/wapiti3
    :alt: Downloads per day on PyPi
    :target: https://pypi.python.org/pypi/wapiti3
.. image:: https://codecov.io/gh/wapiti-scanner/wapiti/branch/master/graph/badge.svg?token=GFEIORAFB8
    :target: https://codecov.io/gh/wapiti-scanner/wapiti

Wapiti is a web vulnerability scanner written in Python.

http://wapiti-scanner.github.io/

Requirements
============
In order to work correctly, Wapiti needs Python 3.x where x is >= 10 (3.10, 3.11, 3.12)

All Python module dependencies will be installed automatically if you use the setup.py script or `pip install wapiti3`

See `INSTALL.md <https://github.com/wapiti-scanner/wapiti/blob/master/INSTALL.md>`__ for more details on installation.

Running Wapiti on Windows can be accomplished through the use of `WSL <https://learn.microsoft.com/en-us/training/modules/get-started-with-windows-subsystem-for-linux/>`__.

How it works
============

Wapiti works as a "black-box" vulnerability scanner,  that means it won't
study the source code of web applications but will work like a  fuzzer,
scanning the pages of the deployed web application, extracting links and
forms  and attacking  the scripts, sending payloads and looking for error
messages, special strings or abnormal behaviors.


General features
================

+ Generates vulnerability reports in various formats (HTML, XML, JSON, TXT, CSV).
+ Can suspend and resume a scan or an attack (session mechanism using sqlite3 databases).
+ Can give you colors in the terminal to highlight vulnerabilities.
+ Different levels of verbosity.
+ Fast and easy way to activate/deactivate attack modules.
+ Adding a payload can be as easy as adding a line to a text file.
+ Configurable number of concurrent tasks to perform HTTP requests.


Browsing features
=================

+ Support HTTP, HTTPS and SOCKS5 proxies.
+ HTTP authentication on the target (Basic, Digest, NTLM)
+ Authentication by filling login forms.
+ Ability to restrain the scope of the scan (domain, folder, page, url).
+ Automatic removal of one or more parameters in URLs.
+ Multiple safeguards against scan endless-loops (for example, limit of values for a parameter).
+ Possibility to set the first URLs to explore (even if not in scope).
+ Can exclude some URLs of the scan and attacks (eg: logout URL).
+ Import cookies from your Chrome or Firefox browser or using the `wapiti-getcookie` tool.
+ Can activate / deactivate SSL certificates verification.
+ Extract URLs from Flash SWF files.
+ Try to extract URLs from javascript (very basic JS interpreter).
+ HTML5 aware (understand recent HTML tags).
+ Several options to control the crawler behavior and limits.
+ Skipping some parameter names during attack.
+ Setting a maximum time for the scan process.
+ Adding some custom HTTP headers or setting a custom User-Agent.
+ Using a Firefox headless browser for crawling
+ Loading your own python code for complicated authentication cases (see `--form-script` option)
+ Adding custom URL or PATH to update Wappalyzer database


Supported attacks
=================

+ SQL Injections (Error based, boolean based, time based) and XPath Injections
+ Cross Site Scripting (XSS) reflected and permanent
+ File disclosure detection (local and remote include, require, fopen,
  readfile...)
+ Command Execution detection (eval(), system(), passtru()...)
+ XXE (Xml eXternal Entity) injection
+ CRLF Injection
+ Search for potentially dangerous files on the server (thank to the Nikto db)
+ Bypass of weak htaccess configurations
+ Search for copies (backup) of scripts on the server
+ Shellshock
+ Folder and file enumeration (DirBuster like)
+ Server Side Request Forgery (through use of an external Wapiti website)
+ Open Redirects
+ Detection of uncommon HTTP methods (like PUT)
+ Basic CSP Evaluator 
+ Brute Force login form (using a dictionary list)
+ Checking HTTP security headers
+ Checking cookie security flags (secure and httponly flags)
+ Cross Site Request Forgery (CSRF) basic detection
+ Fingerprinting of web applications using the Wappalyzer database
+ Enumeration of CMS module
+ Subdomain takeovers detection
+ Log4Shell (CVE-2021-44228) detection
+ Spring4Shell (CVE-2020-5398) detection
+ Check https redirections
+ Check for file upload vulnerabilities
+ Detection of network devices

Wapiti supports both GET and POST HTTP methods for attacks.  
It also supports multipart and can inject payloads in filenames (upload).  
Display a warning when an anomaly is found (for example 500 errors and timeouts)  
Makes the difference between permanent and reflected  XSS vulnerabilities.

Module names
============

The aforementioned attacks are tied to the following module names :

+ backup (Search copies of scripts and archives on the web server)
+ brute_login_form (Brute Force login form using a dictionary list)
+ buster (DirBuster like module)
+ cms (Scan to detect CMS and their versions)
+ cookieflags (Checks Secure and HttpOnly flags)
+ crlf (CR-LF injection in HTTP headers)
+ csp (Detect lack of CSP or weak CSP configuration)
+ csrf (Detects forms not protected against CSRF or using weak anti-CSRF tokens)
+ exec (Code execution or command injection)
+ file (Path traversal, file inclusion, etc)
+ htaccess (Misconfigured htaccess restrictions)
+ htp (Identify web technologies used the HashThePlanet database)
+ http_header (Check HTTP security headers)
+ https_redirect (Check https redirections)
+ log4shell (Detects websites vulnerable to CVE-2021-44228)
+ methods (Look for uncommon available HTTP methods like PUT)
+ network_device (Look for common files to detect network devices)
+ nikto (Look for known vulnerabilities by testing URL existence and checking responses)
+ permanentxss (Rescan the whole target after the xss module execution looking for previously tainted payloads)
+ redirect (Open Redirects)
+ shellshock (Test Shellshock attack, see `Wikipedia <https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29>`__)
+ spring4shell (Detects websites vulnerable to CVE-2020-5398)
+ sql (Error-based and boolean-based SQL injection detection)
+ ssl (Evaluate the security of SSL/TLS certificate configuration, requires `sslscan <https://github.com/rbsec/sslscan>`__)
+ ssrf (Server Side Request Forgery)
+ takeover (Subdomain takeover)
+ timesql (SQL injection vulnerabilities detected with time-based methodology)
+ upload (File upload vulnerabilities)
+ wapp (Not an attack module, retrieves web technologies with versions and categories in use on the target)
+ wp_enum (Enumerate plugins and themes on a Wordpress website)
+ xss (XSS injection module)
+ xxe (XML External Entity attack)

Module names can be given as comma separated list using the "-m" or "--module" option.


How to get the best results
===========================

To find more vulnerabilities (as some attacks are error-based), you can modify
your webserver configurations.

For example, you can set the following values in your PHP configuration :

.. code-block::

    safe_mode = Off
    display_errors = On (recommended)
    magic_quotes_gpc = Off
    allow_url_fopen = On
    mysql.trace_mode = On


Where to get help
=================

In the prompt, just type the following command to get the basic usage :

    wapiti -h

You can also take a look at the manpage (wapiti.1 or wapiti.1.html) for more details on each option.

If you have another question, first check the `FAQ <https://github.com/wapiti-scanner/wapiti/blob/master/doc/FAQ.md>`__

If you find a bug, fill an issue : https://github.com/wapiti-scanner/wapiti/issues

The official wiki can be helpful too :  
https://sourceforge.net/p/wapiti/wiki/browse_pages/


How to help the Wapiti project
==============================

You can :

+ Support the project by making a donation ( http://sf.net/donate/index.php?group_id=168625 )
+ Create or improve attack modules
+ Create or improve report generators and templates
+ Send bugfixes, patches...
+ Write some GUIs
+ Create a tool to convert PCAP files to Wapiti sqlite3 session files
+ Talk about Wapiti around you

Licensing
=========

Wapiti is released under the GNU General Public License version 2 (the GPL).
Source code is available on `Github <https://github.com/wapiti-scanner/wapiti>`__.

Created by Nicolas SURRIBAS.

Sponsors
========

Cyberwatch https://cyberwatch.fr/

Security For Everyone https://securityforeveryone.com/

Disclaimer
==========

Wapiti is a cybersecurity software. It performs security assessments on a provided target, which can lead to malfunctions and crashes on the target, as well as potential data loss.

Usage of Wapiti for attacking a target without prior consent of its owner is illegal. It is the end user's responsibility to obey all applicable local laws.

Developers and people involved in the Wapiti project assume no liability and are not responsible for any misuse or damage caused by this program.
