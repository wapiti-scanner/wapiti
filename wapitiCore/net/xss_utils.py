import re

from bs4 import BeautifulSoup, element


# Note: il n'est pas nécessaire de fermer tous les parents, le noscript suffira
def close_noscript(tag):
    """Return a string with each closing parent tags for escaping a noscript"""
    s = ""
    if tag.findParent("noscript"):
        curr = tag.parent
        while True:
            s += "</{0}>".format(curr.name)
            if curr.name == "noscript":
                break
            curr = curr.parent
    return s


# type/name/tag ex: attrval/img/src
def study(bs_node, parent=None, keyword=""):
    entries = []

    # if parent is None:
    #  print("Keyword is: {0}".format(keyword))
    if keyword in str(bs_node).lower():
        if isinstance(bs_node, element.Tag):
            if keyword in str(bs_node.attrs):

                for k, v in bs_node.attrs.items():
                    if keyword in v:
                        # print("Found in attribute value {0} of tag {1}".format(k, bs_node.name))
                        noscript = close_noscript(bs_node)
                        d = {"type": "attrval", "name": k, "tag": bs_node.name, "noscript": noscript}
                        if d not in entries:
                            entries.append(d)

                    if keyword in k:
                        # print("Found in attribute name {0} of tag {1}".format(k, bs_node.name))
                        noscript = close_noscript(bs_node)
                        d = {"type": "attrname", "name": k, "tag": bs_node.name, "noscript": noscript}
                        if d not in entries:
                            entries.append(d)

            elif keyword in bs_node.name:
                # print("Found in tag name")
                noscript = close_noscript(bs_node)
                d = {"type": "tag", "value": bs_node.name, "noscript": noscript}
                if d not in entries:
                    entries.append(d)

            # recursively search injection points for the same variable
            for x in bs_node.contents:
                for entry in study(x, parent=bs_node, keyword=keyword):
                    if entry not in entries:
                        entries.append(entry)

        elif isinstance(bs_node, element.Comment):
            # print("Found in comment, tag {0}".format(parent.name))
            noscript = close_noscript(bs_node)
            d = {"type": "comment", "parent": parent.name, "noscript": noscript}
            if d not in entries:
                entries.append(d)

        elif isinstance(bs_node, element.NavigableString):
            # print("Found in text, tag {0}".format(parent.name))
            noscript = close_noscript(bs_node)
            d = {"type": "text", "parent": parent.name, "noscript": noscript}
            if d not in entries:
                entries.append(d)

    return entries


# generate a list of payloads based on where in the webpage the js-code will be injected
def generate_payloads(html_code, code, independant_payloads):
    # We must keep the original source code because bs gives us something that may differ...
    soup = BeautifulSoup(html_code, "lxml")
    entries = study(soup, keyword=code)

    payloads = []

    for elem in entries:
        payload = ""
        # Try each case where our string can be found
        # Leave at the first possible exploitation found

        # Our string is in the value of a tag attribute
        # ex: <a href="our_string"></a>
        if elem["type"] == "attrval":
            # print("tag -> {0}".format(elem["tag"]))
            # print(elem["name"])
            code_index = html_code.find(code)
            attrval_index = 0
            before_code = html_code[:code_index]

            # Not perfect but still best than the former rfind
            attr_pattern = "\s*" + elem["name"] + "\s*=\s*"

            # Let's find the last match
            for m in re.finditer(attr_pattern, before_code, flags=re.IGNORECASE):
                attrval_index = m.end()

            attrval = before_code[attrval_index:]
            # between the tag name and our injected attribute there is an equal sign and maybe
            # a quote or a double-quote that we need to close before adding our payload
            if attrval.startswith("'"):
                payload = "'"
            elif attrval.startswith('"'):
                payload = '"'

            # we must deal differently with self-closing tags
            if elem["tag"].lower() in ["img", "input"]:
                payload += "/>"
            else:
                payload += "></" + elem["tag"] + ">"

            payload += elem["noscript"]
            # ok let's send the requests
            for xss, flags in independant_payloads:
                js_code = payload + xss.replace("__XSS__", code)
                if (js_code, flags) not in payloads:
                    payloads.append((js_code, flags))

            if elem["name"].lower() == "src" and elem["tag"].lower() in ["frame", "iframe"]:
                if elem["tag"].lower() == "frame":
                    flags = {"frame_src_javascript"}
                else:
                    flags = {"iframe_src_javascript"}

                js_code = "javascript:String.fromCharCode(0,__XSS__,1);".replace("__XSS__", code)
                if (js_code, flags) not in payloads:
                    payloads.insert(0, (js_code, flags))

        # we control an attribute name
        # ex: <a our_string="/index.html">
        elif elem["type"] == "attrname":  # name,tag
            if code == elem["name"]:
                for xss, flags in independant_payloads:
                    js_code = '>' + elem["noscript"] + xss.replace("__XSS__", code)
                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))

        # we control the tag name
        # ex: <our_string name="column" />
        elif elem["type"] == "tag":
            if elem["value"].startswith(code):
                # use independent payloads, just remove the first character (<)
                for xss, flags in independant_payloads:
                    payload = elem["noscript"] + xss.replace("__XSS__", code)
                    js_code = payload[1:]
                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))
            else:
                for xss, flags in independant_payloads:
                    js_code = "/>" + elem["noscript"] + xss.replace("__XSS__", code)
                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))

        # we control the text of the tag
        # ex: <textarea>our_string</textarea>
        elif elem["type"] == "text":
            if elem["parent"] in ["title", "textarea"]:  # we can't execute javascript in those tags
                if elem["noscript"] != "":
                    payload = elem["noscript"]
                else:
                    payload = "</{0}>".format(elem["parent"])
            elif elem["parent"] == "script":  # Control over the body of a script :)
                # Just check if we can use brackets
                js_code = "String.fromCharCode(0,__XSS__,1)".replace("__XSS__", code)
                flags = {"script_fromcharcode"}
                if (js_code, flags) not in payloads:
                    payloads.insert(0, (js_code, flags))

            for xss, flags in independant_payloads:
                js_code = payload + xss.replace("__XSS__", code)
                if (js_code, flags) not in payloads:
                    payloads.append((js_code, flags))

        # Injection occurred in a comment tag
        # ex: <!-- <div> whatever our_string blablah </div> -->
        elif elem["type"] == "comment":
            payload = "-->"
            if elem["parent"] in ["title", "textarea"]:  # we can't execute javascript in those tags
                if elem["noscript"] != "":
                    payload += elem["noscript"]
                else:
                    payload += "</{0}>".format(elem["parent"])
            elif elem["parent"] == "script":  # Control over the body of a script :)
                # Just check if we can use brackets
                js_code = payload + "String.fromCharCode(0,__XSS__,1)".replace("__XSS__", code)
                flags = {"script_fromcharcode"}
                if (js_code, flags) not in payloads:
                    payloads.insert(0, (js_code, flags))

            for xss, flags in independant_payloads:
                js_code = payload + xss.replace("__XSS__", code)
                if (js_code, flags) not in payloads:
                    payloads.append((js_code, flags))

        html_code = html_code.replace(code, "none", 1)  # Reduce the research zone
    return payloads


def valid_xss_content_type(http_res):
    """Check whether the returned content-type header allow javascript evaluation."""
    # When no content-type is returned, browsers try to display the HTML
    if "content-type" not in http_res.headers:
        return True
    # else only text/html will allow javascript (maybe text/plain will work for IE...)
    if "text/html" in http_res.headers["content-type"]:
        return True
    return False
