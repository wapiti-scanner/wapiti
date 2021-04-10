## How the XXE module and the HTTP endpoint works

The XXE module can perform Out-of-Band attack to attempt to exfiltrate the content of operating system files to make
sure the attack succeed.

The steps are as follows:

### 1. Send the XML payload containing an external DTD to the target 

The module sends a request with a XML payload, either in a parameter or directly as the HTTP request body.
The XML specify the use of an external DTD.
The URL of that DTD will start with the external endpoint URL followed by "dtd/" then several values given in the path.

The URL is in this form :

http://ext-endpoint.tld/dtd/ **session id** / **path id** / **injected parameter (as hex)** / **payload name**.dtd

The session ID is chosen by Wapiti at runtime and generated randomly. It is alphanumeric and 6 characters long.

The path ID is the ID of the HTTP request (used internally by Wapiti in its sqlite3 database)

The injected parameter is the name of the parameter where the payload is injected, and it is hex-encoded.

When the payload is the whole body, this value is "72617720626f6479" which decodes to "raw body".

The payload name is either "linux", "windows" or "linux2" and it will be used later by the endpoint in the attack process.

## 2. The server receives the XML message and fetch the external DTD

The server receives the XML data and process it. It will fetch the DTD URL given in the document.

The endpoint is using Apache mod_rewrite and will redirect the request to the following script on the external endpoint:

/xxe_dtd.php?session_id=**session id**&path_id=**path id**&hex_param=**injected parameter (as hex)**&payload=**payload name**


## 3. The external endpoint reply with a DTD using an external XML entity (SYSTEM)

The script will reply with a dynamically generated DTD containing an external XML entity.

This entity will make the script of the target (if vulnerable) read the content of a file on its system (eg /etc/passwd
if the payload name was "linux") and inject the data in another URL of the external endpoint before calling it.

This last URL that takes place in the attack has a path that starts with "xoxo" and looks like this :

/xoxo/**session id**/**path id**/**injected parameter (as hex)**/**payload (as int)**/**content of exfiltrated file (url-encoded)**

Here the payload was converted to a number because the shorter the URL is, the more we get some room for the exfiltrated data.

Internally the real script (the target of the mod_rewrite rule) called on the external endpoint is the following :

/xxe_store.php?session_id=**session id**&path_id=**path id**&hex_param=**injected parameter (as hex)**&payload=**payload (as int)**&data=**exfiltrated data**


## 3. The external endpoint stores the exfiltrated data along with some metadata

The endpoint receives the exfiltrated data on xxe_store.php and write it to a file under the following path:

./xxe_data/**session id**/**path id**/**injected parameter (as hex)**/

The filename has the following format :

**time of request**-**payload (as int)**-**ip address of the sender**.txt

## 4. Wapiti fetch all metadata for the given session ID

When the XXE module has finished running, Wapiti call the `get_xxe.php` script on the internal endpoint and gives it
the session ID:

http://int-endpoint.tld/get_xxe.tld?session_id= **session id**

The session ID is long enough to prevent being brute-forced.

The `get_xxe.php` script will list every file for the matching session ID, extract the metadata (vulnerable request,
vulnerable parameter, date of exfiltration, payload used, IP of target, size of exfiltrated data, URL of exfiltrated
content) and give all this information to Wapiti which will print those in a human friendly way.
