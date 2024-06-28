## Frequently Asked Questions ##

### What is Wapiti ? ###

Wapiti is a web-application / website vulnerability scanner written in Python3.  
It allows to automate the processing of finding web-based vulnerabilities.  
This is not an exploitation framework like Metasploit, it only does detection.

### How do I install Wapiti on my computer ? ###

Details of installation can be found in the INSTALL.md file.

### What do I need to install Wapiti ? ###

Any operating system with a recent Python3 installation should be ok.

### Is Wapiti still supported for Windows ###

Wapiti won't work out of the box on Microsoft Windows system, but you should be able to run it from inside a WSL environment.  
See this link for more information about WSL: https://docs.microsoft.com/en-us/windows/wsl/

### Can I modify and share the software code ? ###

Sure as long as you respect the GPLv2 license.

### How do I execute Wapiti ? ###

Wapiti is a console tool, so it must be launched from a terminal (Konsole or GnomeTerminal on Linux, etc)  
If you installed Wapiti then the binary should be in your path. Otherwise, you will have to launch it from the bin folder once the archive is uncompressed.  
On Linux and OSX, just typing `wapiti` should work.

### Where can I get some help about options ? ###

The manpage (Linux or HTML version) is the best way to have detailed information about the options.  
If you are really lost, feel free to contact me.

### I have a warning about the ssl module not working ! ###

The `ssl` module requires the [sslscan](binary) to be present in your PATH.  
Check if the software is available with your package manager.

### I have some UnicodeDecodeError as soon as I launch Wapiti ! ###

You must make sure your terminal support unicode characters.  
On Windows you can use the command `chcp 65001` to change the codepage before using Wapiti.

### I found a bug. Where to report ? ###

Please create an issue on https://github.com/wapiti-scanner/wapiti/issues

### Can I help the project ? ###

Sure ! If you have Python3 skills I can give you some tasks to work on.

### I love Wapiti, how to support the project ? ###

Wapiti is a project made on my spare time. If you love the project, a little donation would be welcome :
http://sourceforge.net/donate/index.php?group_id=168625  

### I'm trying to hack a website, can you help me ? ###

Nope.

### Is the proxy option sure ? Will it leak my IP ? ###

The proxy option should work and act as expected. But humans make mistakes. I may have made some mistakes. You may make some mistakes.  
If you plan to hack a 3 letter agency I hope you know exactly what you are doing.

### I was trying to hack a website but Wapiti crashed. Can you help me ? ###

Sure, create an issue on the bug tracker.

### I'm a forensic expert working on a case where Wapiti is used, can you help me ? ###

Yes I can help you understand how Wapiti works and what are the files involved.

### I found some vulnerabilities in a web application using Wapiti, should I mention it ? ###

You don't have to, but it would be appreciated.

### Can I add some attack payloads easily ? ###

Yes, most of the payloads are stored in plain text or .ini files. You just have to add your own.

### Launched a Wapiti scan, it takes sooooooo muuuuuuuuch time ####

Yes it can happen if there is a lot of webpages and/or forms or urls with a lot of inputs.  
There is a lot of available options to reduce the amount of scanned pages. See the manpages.

### I launched Wireshark/tshark/tcpdump/whatever and I don't see any network activity ###

There's some strange behavior that may occur on Windows. Just Ctrl+C and the scan will continue normally.
Well... until the next time the problem occurs :(
Best option for that problem should be to use Linux... sorry MS dudes.

### Why should I use Wapiti and not another vulnerability scanner ? ###

First Wapiti is a free and open-source software, that's a huge difference with some other solutions.  
Wapiti also have the advantage to be usable as an automated task, for example for continuous testing of a web-application.

### Why should I use Wapiti and not SQLmap ? ###

Wapiti and SQLmap are complementary tools doing different things.  
For pentests I usually do a scan with Wapiti then exploit SQLi vulnerabilities with SQLmap.

### Is Wapiti effective ? Do you find vulnerabilities with it ? ###

Yes, it can find a lot. But Wapiti doesn't act like a MITM proxy so it may not find scripts where Ajax (XHR) is involved.  
Don't hesitate to move to OWASP Zed Attack Proxy for in-depth pentesting.

### What about endpoints ? Can I set my own ? ###

An HTTP endpoint is used for some modules in order to see if the target is vulnerable.  
Such modules are currently XXE and SSRF. The endpoint is necessary to see if the target generates an external HTTP request.  
The default endpoint is hosted at wapiti3.ovh so your computer and the target must be able to contact it to check vulnerability results.  
You can set up your own endpoint, all required files can be found here : https://github.com/wapiti-scanner/wapiti/tree/master/endpoint  
You will need URL rewriting to set up the endpoint.  
Wapiti have several options that can be used to specify the endpoint's URL.

### How do you test Wapiti ? ###

Internet is like a box of chocolates: You never know what you're gonna get.  
Broken webpages, malformed links, mixed standards for HTML/XML/XHTML, proprietary technologies, network or protocol issues...
So the only way to make sure Wapiti is Internet proof is to launch it on random targets.  
Don't take it personally, you are helping to make the Internet a safer place.  
The stability of the code is also checked with unittests to prevent regressions.  
Crash reports are also sent to the wapiti3.ovh website so I can try to fix bugs.

### Do you have a personal website ? Twitter ? ###

Yes you can follow me on Twitter @devl00p.  
My website is http://devloop.users.sourceforge.net/  
I write some CTF walkthrough. Articles are in French though.
