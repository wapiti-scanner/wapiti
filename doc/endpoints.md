## What are endpoints used by Wapiti?

Some attack modules of Wapiti will test if a server is vulnerable by trying to make it fetch a given URL under our control.

This is the case for the Server-Side Request Forgery (SSRF) module.

This module will inject the URL of the external endpoint in all parameters of found URLs and forms in the hope that a
vulnerable script will fetch the endpoint URL.

The endpoint PHP script will keep a trace of that request and once the SSRF module has finished, Wapiti will question the
endpoint (using the internal URL) to see if a vulnerable script actually fetched that URL.

## Differences between the external and internal endpoints and why you should set up your own

If you don't define your own endpoint URLs (with `--external-endpoint` and `--internal-endpoint`) then the default
endpoint will be `http://wapiti3.ovh/` for both options.

But you may prefer to set up your own endpoints for several reasons.

The first reason is privacy: even if I (as administrator of the `wapiti3.ovh` domain) don't take a look at collected
data it would be better for you to have full control over this.

The second reason is detection: as it is hardcoded inside the source code, intrusion detection systems may catch requests
to the `wapiti3.ovh` domain.

Finally, if you are doing an audit on a local network, the target may not be able to contact an external domain therefore
you will have to make the endpoint listen on an IP of that network. You may end up with having:

- External endpoint: http://192.168.1.85/ - this is the URL that the target will request
- Internal endpoint: http://127.0.0.1/ - this is the URL that Wapiti will request at the end of the attack to get results

The XXE module also use the endpoints options. The whole process is described in the `doc/xxe_module.md` file.

## What is the DNS endpoint?

The log4shell attack module uses a DNS endpoint to see if a scanned website is vulnerable to the popular log4j vulnerability.

The default endpoint used is dns.wapiti3.ovh which is a DNS server.