                                WAPITI - VERSION 3.0.3
                    Wapiti is a web application security auditor.
                           http://wapiti.sourceforge.io/


Requirements
============
In order to work correctly, Wapiti needs :

+ Python 3.x where x is >= 5 (3.5, 3.6, 3.7...)
+ python-requests ( http://docs.python-requests.org/en/latest/ )
+ BeautifulSoup ( http://www.crummy.com/software/BeautifulSoup/ )
+ yaswfp ( https://github.com/facundobatista/yaswfp )
+ tld ( https://github.com/barseghyanartur/tld )
+ Mako ( https://www.makotemplates.org/ )
+ PySocks ( https://github.com/Anorov/PySocks )

See INSTALL.md for more details on installation.

How it works
============

Wapiti works as a "black-box" vulnerability scanner,  that means it won't
study the source code of web applications but will work like a  fuzzer,
scanning the pages of the deployed web application, extracting links and
forms  and attacking  the scripts, sending payloads and looking for error
messages, special strings or abnormal behaviors.


General features
================

+ Generates vulnerability reports in various formats (HTML, XML, JSON, TXT...).
+ Can suspend and resume a scan or an attack (session mechanism using sqlite3 databases).
+ Can give you colors in the terminal to highlight vulnerabilities.
+ Different levels of verbosity.
+ Fast and easy way to activate/deactivate attack modules.
+ Adding a payload can be as easy as adding a line to a text file.


Browsing features
=================

+ Support HTTP, HTTPS and SOCKS5 proxies.
+ Authentication on the target via several methods : Basic, Digest, Kerberos or NTLM.
+ Ability to restrain the scope of the scan (domain, folder, page, url).
+ Automatic removal of one or more parameters in URLs.
+ Multiple safeguards against scan endless-loops (for example, limit of values for a parameter).
+ Possibility to set the first URLs to explore (even if not in scope).
+ Can exclude some URLs of the scan and attacks (eg: logout URL).
+ Import of cookies (get them with the wapiti-getcookie tool).
+ Can activate / deactivate SSL certificates verification.
+ Extract URLs from Flash SWF files.
+ Try to extract URLs from javascript (very basic JS interpreter).
+ HTML5 aware (understand recent HTML tags).
+ Several options to control the crawler behavior and limits.
+ Skipping some parameter names during attack.
+ Setting a maximum time for the scan process.
+ Adding some custom HTTP headers or setting a custom User-Agent.


Supported attacks
=================

+ Database Injection (PHP/ASP/JSP SQL Injections and XPath Injections)
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
+ DirBuster like
+ Server Side Request Forgery (through use of an external Wapiti website)
+ Open Redirects
+ Detection of uncommon HTTP methods (like PUT)

Wapiti supports both GET and POST HTTP methods for attacks.  
It also supports multipart and can inject payloads in filenames (upload).  
Display a warning when an anomaly is found (for example 500 errors and timeouts)  
Makes the difference  between permanent  and reflected  XSS vulnerabilities.

Module names
============

The aforementioned attacks are tied to the following module names :

+ backup (Search for copies and scripts)
+ blindsql (SQL injection vulnerabilities detected with time-based methodology)
+ buster (DirBuster like module)
+ crlf (CR-LF injection in HTTP headers)
+ delay (Not an attack module, prints the 10 slowest to load webpages of the target)
+ exec (Code execution or command injection)
+ file (Path traversal, file inclusion, etc)
+ htaccess (Misconfigured htaccess restrictions)
+ methods (Look for uncommon availables HTTP methods like PUT)
+ nikto (Look for known vulnerabilities by testing URL existence and checking responses)
+ permanentxss (Rescan the whole target after the xss module execution looking for previously tainted payloads)
+ redirect (Open Redirects)
+ shellshock (Test Shellshock attack, see https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29 )
+ sql (Error-based SQL injection detection)
+ ssrf (Server Side Request Forgery)
+ xss (XSS injection module)
+ xxe (XML External Entity attack)

Module names can be given as comma separated list using the "-m" or "--module" option.


How to get the best results
===========================

To find more vulnerabilities (as some attacks are error-based), you can modify
your webserver configurations.

For example, you can set the following values in your PHP configuration :
```
safe_mode = Off
display_errors = On (recommended)
magic_quotes_gpc = Off
allow_url_fopen = On
mysql.trace_mode = On
```

Where to get help
=================

In the prompt, just type the following command to get the basic usage :

```wapiti -h```

You can also take a look at the manpage (wapiti.1 or wapiti.1.html) for more details on each option.

If you find a bug, fill a ticket on the bugtracker :  
https://sourceforge.net/p/wapiti/bugs/

The official wiki can be helpful too :  
https://sourceforge.net/p/wapiti/wiki/browse_pages/


How to help the Wapiti project
==============================

You can :

+ Support the project by making a donation ( http://sf.net/donate/index.php?group_id=168625 )
+ Create or improve attack modules
+ Create or improve report generators
+ Work on the JS interpreter (lamejs)
+ Send bugfixes, patches...
+ Write some GUIs
+ Create some tools to convert cookies from browsers to Wapiti JSON format
+ Create a tool to convert PCAP files to Wapiti sqlite3 session files
+ Translate Wapiti in your language ( https://www.transifex.com/none-538/wapiti/ )
+ Talk about Wapiti around you


What is included with Wapiti
============================

Wapiti comes with :

+ a modified version of PyNarcissus (MPL 1.1 License),
  see https://github.com/jtolds/pynarcissus
+ Kube CSS framework ( see http://imperavi.com/kube/ ) and jQuery
  for HTML report generation.

Licensing
=========

Wapiti is released under the GNU General Public License version 2 (the GPL).
Source code is available on SourceForge :
https://sourceforge.net/projects/wapiti/
