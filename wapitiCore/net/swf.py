#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2017-2020 Nicolas Surribas
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
import struct

from yaswfp import swfparser
from bs4 import BeautifulSoup

from wapitiCore import parser_name


def looks_like_an_url(string):
    string = string.strip()
    if len(string) < 3:
        return False
    if " " in string or "\t" in string or "\n" in string or "\\" in string:
        return False
    if string.startswith(("http://adobe.com/", "http://www.adobe.com/", ":", "com.", "org.")):
        return False
    if string in {"../", "./"}:
        return False
    if string.startswith(("../", "./")):
        return True
    if string.startswith(("http://", "https://")):
        if len(string) > 12:
            return True
        return False
    if ":" in string:
        return False
    if string.startswith("/") or string.endswith("/"):
        return True
    for ext in {
        ".php", ".asp", ".php4", ".php5", ".html", ".xhtml", ".htm", ".swf", ".xml", ".pl", ".cgi", ".rb", ".py", ".js",
        ".pdf", ".gif", ".png", ".jpg", ".svg", ".jpeg", ".mp3", ".wav", ".aspx"
    }:
        if ext in string and not string.startswith(ext) and "(" not in string:
            return True
    if "?" in string and "=" in string:
        return True
    return False


def read_u30(data):
    i = 0
    nb = 0
    byte_pos = 0
    while True:
        x = data[i]
        bits = x & 127
        i += 1
        nb += bits << byte_pos
        byte_pos += 7
        if not x & 128:
            break
    return nb, i


def new_read_u30(stream):
    nb = 0
    byte_pos = 0
    while True:
        x = stream.read(1)[0]
        bits = x & 127
        nb += bits << byte_pos
        byte_pos += 7
        if not x & 128:
            break
    return nb


def read_abc(data):
    name_len = data.find(b'\0')
    minor, major = struct.unpack("HH", data[name_len + 1: name_len + 5])

    i = name_len + 5
    nb, x = read_u30(data[i:])
    i += x
    for __ in range(nb - 1):
        z, x = read_u30(data[i:])
        i += x

    # Read the array of uintegers :
    nb, x = read_u30(data[i:])
    i += x
    for __ in range(nb - 1):
        z, x = read_u30(data[i:])
        i += x

    # Pass the array of doubles
    nb, x = read_u30(data[i:])
    i += x
    if nb > 0:
        i += (nb - 1) * 8

    # Process the array of strings
    nb, x = read_u30(data[i:])
    i += x
    for __ in range(nb - 1):
        nb, x = read_u30(data[i:])
        i += x
        string = data[i: i + nb].decode().strip()
        if "<a href=" in string:
            soup = BeautifulSoup(string, parser_name)
            for link in soup.find_all("a", href=True):
                yield link["href"]
        else:
            yield string
        i += nb


def analyze_action(action):
    # Actions known to be uninteresting
    # if action.name in {
    #     "ActionStop", "ButtonCondAction", "ActionAdd2", "ActionGetVariable", "ActionPop",
    #     "ActionGetMember", "ActionSubtract", "ActionSetVariable", "ActionSetMember", "ActionGetURL2",
    #     "ActionDefineLocal", "ActionCallMethod", "ActionDefineFunction2", "ActionPlay",
    #     "ActionGotoFrame", "ActionStopSounds", "ActionInitArray", "ActionDivide", "ActionNot", "ActionIf",
    #     "ActionReturn", "ActionGreater", "ActionNewObject", "ActionEquals2", "ActionIncrement", "ActionToNumber",
    #     "ActionTrace", "ActionToString", "ActionMultiply", "ActionJump", "ActionTargetPath", "ActionLess2",
    #     "ActionDefineFunction", "ActionStoreRegister", "ActionDecrement", "ActionWaitForFrame", "ActionNextFrame",
    #     "ActionSetTarget", "ActionGetProperty", "ActionCallFunction", "ActionGotoFrame2", "ActionToInteger",
    #     "ActionSetTarget2", "ActionInitObject", "ActionSetProperty", "ActionGoToLabel", "ActionNewMethod"
    # }:
    #     return None

    if action.name == "ActionPush":
        if action.Type == 0:
            yield action.String
    elif action.name == "ActionGetURL":
        yield action.UrlString
    elif action.name == "ButtonCondAction":
        if hasattr(action, "Actions"):
            for subaction in action.Actions:
                yield from analyze_action(subaction)
    elif action.name == "ActionConstantPool":
        if hasattr(action, "ConstantPool"):
            for constant in action.ConstantPool:
                yield constant


def analyze_tag(tag):
    if tag.name in [
        "ShowFrame", "PlaceObject2", "DefineText", "DefineBits", "RemoveObject2", "DefineShape", "DefineFontName",
        "FrameLabel", "DefineShape4", "DefineFont3", "DefineShape2", "JPEGTables", "CSMTextSettings",
        "DefineFontAlignZones", "SetBackgroundColor", "Protect", "FileAttributes", "ExportAssets", "DefineShape3",
        "Metadata", "ScriptLimits", "EnableDebugger2", "SymbolClass", "DefineBitsJPEG3", "DefineBitsLossless2",
        "PlaceObject3", "DefineSceneAndFrameLabelData", "DefineBitsJPEG2", "DefineFont2", "DefineFontInfo2",
        "DefineFont", "DefineMorphShape", "DefineFontInfo", "StartSound", "DefineSound", "DefineButtonSound",
        "SoundStreamHead2", "SoundStreamHead", "SoundStreamBlock", "DefineBitsLossless", "SetTabIndex"
    ]:
        return

    if tag.name == "DefineSprite":
        for control_tag in tag.ControlTags:
            yield from analyze_tag(control_tag)
            # print(control_tag)
    elif tag.name == "DoABC":
        # 82
        yield from read_abc(tag.raw_payload[4:])
    elif tag.name == "DefineEditText":
        # 37
        if tag.HasText and tag.HTML:
            soup = BeautifulSoup(tag.InitialText, parser_name)
            for link in soup.find_all("a", href=True):
                yield link["href"]
    elif tag.name in ["DoAction", "DoInitAction", "DefineButton2"]:
        if hasattr(tag, "Actions"):
            for action in tag.Actions:
                for url in analyze_action(action):
                    if url:
                        yield url


def extract_links_from_swf(file):
    swf = swfparser.SWFParser(file)
    urls = set()
    for tag in swf.tags:
        for text in analyze_tag(tag):
            if looks_like_an_url(text):
                urls.add(text)
    return list(urls)


if __name__ == "__main__":
    import requests

    # resp = requests.get("http://[::1]:8000/action.swf", stream=True)
    resp = requests.get("http://127.0.0.1/wivet/pages/wivet1.swf", stream=True)
    for link in extract_links_from_swf(resp.raw):
        print(link)
