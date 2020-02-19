import re

from bs4 import BeautifulSoup, element

# Everything under those tags will be treated as text
NONEXEC_PARENTS = {
    "iframe",
    "noframes",
    "noembed",
    "noscript",
    "plaintext",
    "style",
    "template",
    "textarea",
    "title",
    "xmp"
}

CSP_HEADERS = {"content-security-policy", "x-content-security-policy", "x-webkit-csp"}


def find_non_exec_parent(tag):
    """Return a string with each closing parent tags for escaping a noscript"""
    no_exec_parent = ""
    for parent in tag.parents:
        if parent and parent.name in NONEXEC_PARENTS:
            no_exec_parent = parent.name

    return no_exec_parent


# type/name/tag ex: attrval/img/src
def get_context(bs_node, keyword, parent=None, ):
    entries = []

    # if parent is None:
    #  print("Keyword is: {0}".format(keyword))
    if keyword in str(bs_node).lower():
        if isinstance(bs_node, element.Tag):
            if keyword in str(bs_node.attrs):

                for k, v in bs_node.attrs.items():
                    if keyword in v:
                        # print("Found in attribute value {0} of tag {1}".format(k, bs_node.name))
                        bad_parent = find_non_exec_parent(bs_node)
                        d = {"type": "attrval", "name": k, "tag": bs_node.name, "non_exec_parent": bad_parent}
                        if d not in entries:
                            entries.append(d)

                    if keyword in k:
                        # print("Found in attribute name {0} of tag {1}".format(k, bs_node.name))
                        bad_parent = find_non_exec_parent(bs_node)
                        d = {"type": "attrname", "name": k, "tag": bs_node.name, "non_exec_parent": bad_parent}
                        if d not in entries:
                            entries.append(d)

            elif keyword in bs_node.name:
                # print("Found in tag name")
                bad_parent = find_non_exec_parent(bs_node)
                d = {"type": "tag", "value": bs_node.name, "non_exec_parent": bad_parent}
                if d not in entries:
                    entries.append(d)

            # recursively search injection points for the same variable
            for x in bs_node.contents:
                for entry in get_context(x, keyword, parent=bs_node):
                    if entry not in entries:
                        entries.append(entry)

        elif isinstance(bs_node, element.Comment):
            # print("Found in comment, tag {0}".format(parent.name))
            bad_parent = find_non_exec_parent(bs_node)
            d = {"type": "comment", "parent": parent.name, "non_exec_parent": bad_parent}
            if d not in entries:
                entries.append(d)

        elif isinstance(bs_node, element.NavigableString):
            # print("Found in text, tag {0}".format(parent.name))
            bad_parent = find_non_exec_parent(bs_node)
            d = {"type": "text", "parent": parent.name, "non_exec_parent": bad_parent}
            if d not in entries:
                entries.append(d)

    return entries


# generate a list of payloads based on where in the webpage the js-code will be injected
def generate_payloads(html_code, code, independant_payloads):
    # We must keep the original source code because bs gives us something that may differ...
    soup = BeautifulSoup(html_code, "html.parser")
    entries = get_context(soup, code)

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
            attr_pattern = r"\s*" + elem["name"] + r"\s*=\s*"

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

            if elem["non_exec_parent"]:
                payload += "</" + elem["non_exec_parent"] + ">"

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
                    js_code = '>'
                    if elem["non_exec_parent"]:
                        payload += "</" + elem["non_exec_parent"] + ">"
                    js_code += xss.replace("__XSS__", code)

                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))

        # we control the tag name
        # ex: <our_string name="column" />
        elif elem["type"] == "tag":
            if elem["value"].startswith(code):
                # use independent payloads, just remove the first character (<)
                for xss, flags in independant_payloads:
                    payload = ""
                    if elem["non_exec_parent"]:
                        payload += "</" + elem["non_exec_parent"] + ">"
                    payload += xss.replace("__XSS__", code)

                    js_code = payload[1:]
                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))
            else:
                for xss, flags in independant_payloads:
                    js_code = "/>"
                    if elem["non_exec_parent"]:
                        payload += "</" + elem["non_exec_parent"] + ">"
                    js_code += xss.replace("__XSS__", code)

                    if (js_code, flags) not in payloads:
                        payloads.append((js_code, flags))

        # we control the text of the tag
        # ex: <textarea>our_string</textarea>
        elif elem["type"] == "text":
            if elem["parent"] in ["script", "title", "textarea"]:
                # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
                # will be executed if we have partial control over a script tag content, so let's escape them
                if elem["non_exec_parent"] != "":
                    payload = "</" + elem["non_exec_parent"] + ">"
                else:
                    payload = "</{0}>".format(elem["parent"])

            for xss, flags in independant_payloads:
                js_code = payload + xss.replace("__XSS__", code)
                if (js_code, flags) not in payloads:
                    payloads.append((js_code, flags))

        # Injection occurred in a comment tag
        # ex: <!-- <div> whatever our_string blablah </div> -->
        elif elem["type"] == "comment":
            payload = "-->"
            if elem["parent"] in ["script", "title", "textarea"]:
                # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
                # will be executed if we have partial control over a script tag content, so let's escape them
                if elem["non_exec_parent"] != "":
                    payload += "</" + elem["non_exec_parent"] + ">"
                else:
                    payload += "</{0}>".format(elem["parent"])

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


def has_csp(response):
    headers = {header.lower() for header in response.headers}
    if CSP_HEADERS & headers:
        return True

    for meta_http in response.soup.find_all("meta", attrs={"http-equiv": True}):
        if meta_http["http-equiv"].lower().strip() in CSP_HEADERS:
            return True

    return False


if __name__ == "__main__":
    from pprint import pprint

    source_code = """<html>
    <body>
    <title>yolo</title>
    <a href="yolo">hello</a>
    <textarea><strong>yolo</strong></textarea>
    <!-- <div><p style="yolo">test</p></div> -->
    </body>
    </html>
    """

    my_soup = BeautifulSoup(source_code, "html.parser")
    pprint(get_context(my_soup, "yolo"))
