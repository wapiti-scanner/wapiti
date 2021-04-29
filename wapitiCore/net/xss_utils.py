# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2020-2021 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from configparser import ConfigParser
from typing import Tuple, List
from html.parser import attrfind_tolerant
from urllib.parse import urlparse

from bs4 import BeautifulSoup, element

from wapitiCore.attack.attack import PayloadType, Flags, random_string

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
    "xmp",
    "frameset"
}


def find_non_exec_parent(tag):
    """Return the tag name of the most upper parent preventing JS execution"""
    no_exec_parent = ""
    for parent in tag.parents:
        if parent and parent.name in NONEXEC_PARENTS:
            no_exec_parent = parent.name

    return no_exec_parent


def is_context_executable(node):
    """Returns whether the current tag doesn't follows a tag that stop JS execution (such as frameset)."""
    # Search for any frameset sat that appeared before in the DOM but weren't parent
    if set(node.find_all_previous("frameset")) - set(node.find_parents("frameset")):
        return False
    return True


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


def get_similar_case_replacement(original_keyword, new_keyword) -> str:
    assert len(original_keyword) == len(new_keyword)
    result = ""
    for old_char, new_char in zip(original_keyword, new_keyword):
        if old_char.islower():
            result += new_char.lower()
        else:
            result += new_char.upper()
    return result


def replace_with_unique_values(text: str, keyword: str) -> Tuple[str, List[str]]:
    new_text = text
    lower_text = text.lower()
    start = 0
    taints = []
    while True:
        try:
            start = lower_text.index(keyword, start)
        except ValueError:
            break

        end = start + len(keyword)
        old_string = text[start:end]
        replacement = get_similar_case_replacement(old_string, random_string("x", len(old_string)))
        taints.append(replacement)
        new_text = new_text.replace(old_string, replacement, 1)
        start = end

    return new_text, taints


def put_back_code_in_context(context, tainted_code, original_code):
    for key, value in context.items():
        if isinstance(value, str):
            context[key] = value.replace(tainted_code, original_code)


def find_separator(html_code, tainted_attr_value, tag_name):
    lower_code = html_code.lower()
    code_index = lower_code.index(tainted_attr_value)
    tag_index = lower_code.rindex("<" + tag_name, 0, code_index)
    tag_end = lower_code.index(">", code_index + len(tainted_attr_value))
    attributes_string = lower_code[tag_index + len(tag_name) + 1:tag_end]
    for __, __, attrvalue in attrfind_tolerant.findall(attributes_string):
        if tainted_attr_value in attrvalue:
            if attrvalue[:1] == '\'' == attrvalue[-1:] or attrvalue[:1] == '"' == attrvalue[-1:]:
                return attrvalue[:1]
    return ""


# type/name/tag ex: attrval/img/src
def get_context_list(html_code, original_keyword):
    tainted_code, taints = replace_with_unique_values(html_code, original_keyword)
    root_node = BeautifulSoup(tainted_code, "html.parser")
    context_list = []

    #  print("Keyword is: {0}".format(keyword))
    for keyword in taints:
        keyword = keyword.lower()
        # if keyword in found_taints:
        #     continue

        for node in root_node.descendants:

            # Several taints may be found in the same node but a taint will appear only once in the code
            if keyword in str(node).lower():
                if isinstance(node, element.Tag) and is_context_executable(node):
                    events = set(name for name in node.attrs.keys() if name.startswith("on"))
                    if keyword in str(node.attrs).lower():
                        for attr_name, attr_value in node.attrs.items():
                            # Be careful: attr_value may be a list, for example with attribute "rel" of tag "link"
                            if keyword in str(attr_value).lower():
                                # print("Found in attribute value {0} of tag {1}".format(attr_name, bs_node.name))
                                bad_parent = find_non_exec_parent(node)

                                try:
                                    separator = find_separator(tainted_code, keyword, node.name)
                                except ValueError:
                                    separator = ""

                                context = {
                                    "type": "attrval",
                                    "name": attr_name,
                                    "tag": node.name,
                                    "non_exec_parent": bad_parent,
                                    "events": events,
                                    "separator": separator
                                }

                                special_attributes = get_special_attributes(node)
                                if special_attributes:
                                    context["special_attributes"] = special_attributes

                                put_back_code_in_context(context, keyword, original_keyword)
                                if context not in context_list:
                                    context_list.append(context)

                            if keyword in attr_name:
                                # print("Found in attribute name {0} of tag {1}".format(attr_name, bs_node.name))
                                bad_parent = find_non_exec_parent(node)
                                context = {
                                    "type": "attrname",
                                    "name": attr_name,
                                    "tag": node.name,
                                    "non_exec_parent": bad_parent,
                                    "events": events
                                }

                                special_attributes = get_special_attributes(node)
                                if special_attributes:
                                    context["special_attributes"] = special_attributes

                                put_back_code_in_context(context, keyword, original_keyword)
                                if context not in context_list:
                                    context_list.append(context)

                    elif keyword in node.name.lower():
                        # print("Found in tag name")
                        bad_parent = find_non_exec_parent(node)
                        context = {
                            "type": "tag",
                            "value": node.name,
                            "non_exec_parent": bad_parent,
                            "events": events
                        }

                        put_back_code_in_context(context, keyword, original_keyword)
                        if context not in context_list:
                            context_list.append(context)

                elif isinstance(node, element.Comment) and is_context_executable(node):
                    # print("Found in comment, tag {0}".format(parent.name))
                    bad_parent = find_non_exec_parent(node)
                    context = {"type": "comment", "parent": node.parent.name, "non_exec_parent": bad_parent}
                    put_back_code_in_context(context, keyword, original_keyword)
                    if context not in context_list:
                        context_list.append(context)

                elif isinstance(node, element.NavigableString) and is_context_executable(node):
                    # print("Found in text, tag {0}".format(parent.name))
                    bad_parent = find_non_exec_parent(node)
                    context = {"type": "text", "parent": node.parent.name, "non_exec_parent": bad_parent}
                    put_back_code_in_context(context, keyword, original_keyword)
                    if context not in context_list:
                        context_list.append(context)

    return context_list


def load_payloads_from_ini(filename, external_endpoint):
    config_reader = ConfigParser(interpolation=None)
    config_reader.read_file(open(filename))
    payloads = []
    external_endpoint = external_endpoint if external_endpoint.endswith('/') else external_endpoint + "/"
    parts = urlparse(external_endpoint)
    proto_endpoint = parts.netloc + parts.path

    for section in config_reader.sections():
        payload = config_reader[section]["payload"]
        value = config_reader[section]["value"]

        clean_payload = payload.strip(" \n")
        clean_payload = clean_payload.replace("[TAB]", "\t")
        clean_payload = clean_payload.replace("[LF]", "\n")
        clean_payload = clean_payload.replace("[EXTERNAL_ENDPOINT]", external_endpoint)
        clean_payload = clean_payload.replace("[PROTO_ENDPOINT]", proto_endpoint)

        clean_value = value.replace("[EXTERNAL_ENDPOINT]", external_endpoint)
        clean_value = clean_value.replace("[PROTO_ENDPOINT]", proto_endpoint)

        infos = {
            "name": section,
            "payload": clean_payload,
            "tag": config_reader[section]["tag"].split(","),
            "attribute": config_reader[section]["attribute"],
            "value": clean_value,
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
            # Payload keeping the tag open
            if context["tag"] in payload_infos["tag"] and payload_infos["attribute"] not in context["events"]:
                if not context["separator"]:
                    attr_separator = " "
                    value_separator = ""
                else:
                    attr_separator = value_separator = context["separator"]

                if payload_infos["tag"] == ["frame"] and payload_infos["attribute"] == "src":
                    # This is a special case... Maybe we should improve that kind of behavior by having something
                    # similar to the match_type (from xssPayloads.ini) in the context
                    js_code = payload_infos["payload"].replace("__XSS__", code)
                else:
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

        else:
            js_code = context["separator"]
            # we must deal differently with self-closing tags
            # see https://developer.mozilla.org/en-US/docs/Glossary/empty_element for reference
            if context["tag"].lower() in [
                    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
                    "source", "track", "wbr",
                    "frame"  # Not in Mozilla list but I guess it is because it is deprecated
            ]:
                # We don't even need a slash to mark the end of the tag
                js_code += ">"
            else:
                js_code += "></" + context["tag"] + ">"

            if context["non_exec_parent"] == "frameset":
                if payload_infos["tag"] != ["frame"]:
                    continue
            elif context["non_exec_parent"]:
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

    if context["parent"] in ["script", "title", "textarea", "style"]:
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
def generate_payloads(html_code, code, payload_file, external_endpoint="http://wapiti3.ovh/"):
    # We must keep the original source code because bs gives us something that may differ...
    context_list = get_context_list(html_code, code)
    payload_list = load_payloads_from_ini(payload_file, external_endpoint)

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


if __name__ == "__main__":
    from pprint import pprint

    SOURCE_CODE = """<html>
    <head><title>Hello injection</title>
    <body>
    <a href="injection">General Kenobi</a>
    <!-- injection -->
    <input type=checkbox injection />
    <noscript><b>injection</b></noscript>
    </body>
    </html>
    """

    pprint(get_context_list(SOURCE_CODE, "injection"))
