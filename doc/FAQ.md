## Frequently Asked Questions ##

### What is Wapiti ? ###

Wapiti is a web-application / website vulnerability scanner written in Python3.  
It allow to automate the processing of finding web-based vulnerabilities.  
This is not an exploitation framework like Metasploit, it only does detection.

### How do I install Wapiti on my computer ? ###

Details of installation can be found in the INSTALL.md file.

### What do I need to install Wapiti ? ###

Any operating system with a recent Python3 installation should be ok.

### Will you release a standalone Windows executable like the one made for Wapiti 2.3.0 ? ###

I'd like to but Microsoft make it so hard to actually doing it. py2exe and pyinstaller seems broken with latests Windows versions.

### Can I modify and share the software code ? ###

Sure as long as you respect the GPLv2 license.

### How do I execute Wapiti ? ###

Wapiti is a console tool so it must be launched from a terminal (cmd.exe on Windows, Konsole or GnomeTerminal on Linux, etc)  
If you installed Wapiti then the binary should be in your path. Otherwise you will have to launch it from the bin folder once the archive is uncompressed.  
On Linux and OSX, just typing `wapiti` should work.  
On Windows you will have to specify the interpreter (`python wapiti`).

### Where can I get some help about options ? ###

The manpage (Linux or HTML version) is the best way to have detailed informations about the options.  
If you are really lost, feel free to contact me.

### I have some UnicodeDecodeError as soon as I launch Wapiti ! ###

You must make sure your terminal support unicode characters.  
On Windows you can use the command `chcp 65001` to change the codepage before using Wapiti.

### I found a bug. Where to report ? ###

Please create an issue on https://sourceforge.net/p/wapiti/bugs/

### Can I help the project ? ###

Sure ! If you have Python3 skills I can give you some tasks to work on.  
If you are not in development you can help translate Wapiti in your language (see https://www.transifex.com/none-538/wapiti/ )

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

Yes, most of the payloads are stored in plain text or .ini files. You just have to add your owns.

### Launched a Wapiti scan, it takes sooooooo muuuuuuuuch time ####

Yes it can happens if there is lot of webpages and/or forms or urls with lot of inputs.  
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
You can set up your own endpoint, all required files can be found here : https://sourceforge.net/p/wapiti/git/ci/master/tree/endpoint/  
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
I write some CTF walkthrough. Articles are in french though.
