import re
from configparser import ConfigParser

from bs4 import BeautifulSoup, element

from wapitiCore.attack.attack import PayloadType, Flags


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


def get_special_attributes(node):
    specials = set()
    # We don't care about the value of the following attributes but we need to know if they are present
    for attribute in ("href", "src", "style"):
        if attribute in node.attrs:
            specials.add(attribute)

    if "type" in node.attrs:
        specials.add("type={}".format(node.attrs["type"].lower()))
    if "rel" in node.attrs:
        # BeautifulSoup returns a list for rel attribute.
        specials.add("rel={}".format(node.attrs["rel"][0].lower()))
    return specials


# type/name/tag ex: attrval/img/src
def get_context_list(html_code, keyword, bs_node=None):
    if bs_node is None:
        bs_node = BeautifulSoup(html_code, "html.parser")

    context_list = []

    # if parent is None:
    #  print("Keyword is: {0}".format(keyword))
    if keyword in str(bs_node).lower():
        if isinstance(bs_node, element.Tag):
            events = set(name for name in bs_node.attrs.keys()if name.startswith("on"))
            if keyword in str(bs_node.attrs):
                for attr_name, attr_value in bs_node.attrs.items():
                    if keyword in attr_value:
                        # print("Found in attribute value {0} of tag {1}".format(attr_name, bs_node.name))
                        bad_parent = find_non_exec_parent(bs_node)

                        code_index = html_code.find(keyword)
                        attrval_index = 0
                        before_code = html_code[:code_index]

                        # Not perfect but still best than the former rfind
                        attr_pattern = r"\s*" + attr_name + r"\s*=\s*"

                        # Let's find the last match
                        for match in re.finditer(attr_pattern, before_code, flags=re.IGNORECASE):
                            attrval_index = match.end()

                        attrval = before_code[attrval_index:]
                        # between the tag name and our injected attribute there is an equal sign and maybe
                        # a quote or a double-quote that we need to close before adding our payload
                        if attrval.startswith("'"):
                            separator = "'"
                        elif attrval.startswith('"'):
                            separator = '"'
                        else:
                            separator = ""

                        context = {
                            "type": "attrval",
                            "name": attr_name,
                            "tag": bs_node.name,
                            "non_exec_parent": bad_parent,
                            "events": events,
                            "separator": separator
                        }

                        special_attributes = get_special_attributes(bs_node)
                        if special_attributes:
                            context["special_attributes"] = special_attributes

                        if context not in context_list:
                            context_list.append(context)

                    if keyword in attr_name:
                        # print("Found in attribute name {0} of tag {1}".format(attr_name, bs_node.name))
                        bad_parent = find_non_exec_parent(bs_node)
                        context = {
                            "type": "attrname",
                            "name": attr_name,
                            "tag": bs_node.name,
                            "non_exec_parent": bad_parent,
                            "events": events
                        }

                        special_attributes = get_special_attributes(bs_node)
                        if special_attributes:
                            context["special_attributes"] = special_attributes

                        if context not in context_list:
                            context_list.append(context)

            elif keyword in bs_node.name:
                # print("Found in tag name")
                bad_parent = find_non_exec_parent(bs_node)
                context = {
                    "type": "tag",
                    "value": bs_node.name,
                    "non_exec_parent": bad_parent,
                    "events": events
                }

                if context not in context_list:
                    context_list.append(context)

            # recursively search injection points for the same variable
            for child_node in bs_node.children:
                for context in get_context_list(html_code, keyword, bs_node=child_node):
                    # Remove the current injection point before going deeper
                    html_code = html_code.replace(keyword, "A" * len(keyword), 1)  # Reduce the research zone
                    if context not in context_list:
                        context_list.append(context)

        elif isinstance(bs_node, element.Comment):
            # print("Found in comment, tag {0}".format(parent.name))
            bad_parent = find_non_exec_parent(bs_node)
            context = {"type": "comment", "parent": bs_node.parent.name, "non_exec_parent": bad_parent}
            if context not in context_list:
                context_list.append(context)

        elif isinstance(bs_node, element.NavigableString):
            # print("Found in text, tag {0}".format(parent.name))
            bad_parent = find_non_exec_parent(bs_node)
            context = {"type": "text", "parent": bs_node.parent.name, "non_exec_parent": bad_parent}
            if context not in context_list:
                context_list.append(context)

    return context_list


def load_payloads_from_ini(filename):
    config_reader = ConfigParser(interpolation=None)
    config_reader.read_file(open(filename))
    payloads = []

    for section in config_reader.sections():
        payload = config_reader[section]["payload"]

        clean_payload = payload.strip(" \n")
        clean_payload = clean_payload.replace("[TAB]", "\t")
        clean_payload = clean_payload.replace("[LF]", "\n")

        infos = {
            "name": section,
            "payload": clean_payload,
            "tag": config_reader[section]["tag"].split(","),
            "attribute": config_reader[section]["attribute"],
            "value": config_reader[section]["value"],
            "case_sensitive": config_reader.getboolean(section, "case_sensitive", fallback=True),
            "close_tag": config_reader.getboolean(section, "close_tag", fallback=True)
        }

        if "requirements" in config_reader[section]:
            infos["requirements"] = set(config_reader[section]["requirements"].split(","))

        payloads.append(infos)

    return payloads


def meet_requirements(payload_requirements, special_attributes):
    # payload_requirements is a set of attr_name or attr_name=value strings
    payload_prefix = ""
    for requirement in payload_requirements:
        if "!" not in requirement and requirement not in special_attributes:  # Condition not met but we may fix it
            if "=" in requirement:
                # Hardest case: Make sure there isn't an attribute with the same name but different value (conflict)
                expected_attribute, expected_value = requirement.split("=")
                if any(attribute.startswith(expected_attribute + "=") for attribute in special_attributes):
                    raise RuntimeError("Requirement cannot be met")
            else:
                # We just name the attribute to appear whatever the value
                expected_attribute = requirement
                expected_value = "z"  # Can be anything

            payload_prefix += "[ATTR_SEP]{}=[VALUE_SEP]{}".format(expected_attribute, expected_value)
        elif "!" in requirement:
            if requirement.replace("!", "") in special_attributes:
                raise RuntimeError("Requirement cannot be met")

    return payload_prefix


def apply_attrval_context(context, payloads, code):
    # Our string is in the value of a tag attribute
    # ex: <a href="our_string"></a>
    result = []

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            if context["tag"] in payload_infos["tag"] and payload_infos["attribute"] not in context["events"]:
                if not context["separator"]:
                    attr_separator = " "
                    value_separator = ""
                else:
                    attr_separator = value_separator = context["separator"]

                try:
                    js_code = "y"  # Not empty value to force non-fuzzy HTML interpretation
                    js_code += meet_requirements(
                        payload_infos.get("requirements", []),
                        context.get("special_attributes", [])
                    )
                    js_code += payload_infos["payload"].replace("__XSS__", code)
                    js_code = js_code.replace("[ATTR_SEP]", attr_separator)
                    js_code = js_code.replace("[VALUE_SEP]", value_separator)
                except RuntimeError:
                    continue

                result.append((js_code, Flags(type=PayloadType.xss_non_closing_tag, section=payload_infos["name"])))

            # if context["name"].lower() == "src" and context["tag"].lower() in ["frame", "iframe"]:
            #     if context["tag"].lower() == "frame":
            #         flags = {"frame_src_javascript"}
            #     else:
            #         flags = {"iframe_src_javascript"}
            #
            #     js_code = "javascript:String.fromCharCode(0,__XSS__,1);".replace("__XSS__", code)
            #     if (js_code, flags) not in payloads:
            #         payloads.insert(0, (js_code, flags))
        else:
            js_code = context["separator"]
            # we must deal differently with self-closing tags
            if context["tag"].lower() in ["img", "input"]:
                js_code += "/>"
            else:
                js_code += "></" + context["tag"] + ">"

            if context["non_exec_parent"]:
                js_code += "</" + context["non_exec_parent"] + ">"

            js_code += payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_attrname_context(context, payloads, code):
    # we control an attribute name
    # ex: <a our_string="/index.html">
    result = []

    if code == context["name"]:
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = '>'
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)

                result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_tagname_context(context, payloads, code):
    # we control the tag name
    # ex: <our_string name="column" />
    result = []

    if context["value"].startswith(code):
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = ""
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)

                js_code = js_code[1:]  # use independent payloads, just remove the first character (<)
                result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))
    else:
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = "/>"
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)
                result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_text_context(context, payloads, code):
    # we control the text of the tag
    # ex: <textarea>our_string</textarea>
    result = []
    prefix = ""

    if context["parent"] in ["script", "title", "textarea"]:
        # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
        # will be executed if we have partial control over a script tag content, so let's escape them
        if context["non_exec_parent"] != "":
            prefix = "</" + context["non_exec_parent"] + ">"
        else:
            prefix = "</{0}>".format(context["parent"])

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            # do new stuff
            pass
        else:
            js_code = prefix + payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_comment_context(context, payloads, code):
    # Injection occurred in a comment tag
    # ex: <!-- <div> whatever our_string blablah </div> -->
    result = []

    prefix = "-->"
    if context["parent"] in ["script", "title", "textarea"]:
        # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
        # will be executed if we have partial control over a script tag content, so let's escape them
        if context["non_exec_parent"] != "":
            prefix += "</" + context["non_exec_parent"] + ">"
        else:
            prefix += "</{0}>".format(context["parent"])

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            # do new stuff
            pass
        else:
            js_code = prefix + payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_context(context, payloads, code):
    func = {
        "attrval": apply_attrval_context,
        "attrname": apply_attrname_context,
        "tag": apply_tagname_context,
        "text": apply_text_context,
        "comment": apply_comment_context
    }[context["type"]]

    return func(context, payloads, code)


# generate a list of payloads based on where in the webpage the js-code will be injected
def generate_payloads(html_code, code, payload_file):
    # We must keep the original source code because bs gives us something that may differ...
    context_list = get_context_list(html_code, code)
    payload_list = load_payloads_from_ini(payload_file)

    payloads_and_flags = []

    for context in context_list:

        for context_payload in apply_context(context, payload_list, code):
            if context_payload not in payloads_and_flags:
                payloads_and_flags.append(context_payload)

    return payloads_and_flags


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
    <head><title>Hello injection</title>
    <body>
    <a href="injection">General Kenobi</a>
    <!-- injection -->
    <input type=checkbox injection />
    <noscript><b>injection</b></noscript>
    </body>
    </html>
    """

    pprint(get_context_list(source_code, "injection"))
