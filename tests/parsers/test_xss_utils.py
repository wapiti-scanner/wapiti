import respx
import httpx
import pytest

from wapitiCore.parsers.html_parser import Html
from wapitiCore.net.xss_utils import get_context_list, valid_xss_content_type, meet_requirements, \
    find_separator
from wapitiCore.net.csp_utils import has_csp_header, has_csp_meta
from wapitiCore.net.crawler import Response


def test_title_context():
    html = """<html>
    <head><title><strong>injection</strong></title>
    <body>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "title", "parent": "strong", "type": "text"}
    ]


def test_noscript_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noscript>
    <textarea>
    <a href="injection">General Kenobi</a>
    <textarea>
    </noscript>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "non_exec_parent": "noscript",
            "tag": "a",
            "name": "href",
            "type": "attrval",
            "separator": "\"",
            "events": set(),
            "special_attributes": {"href"}
        }
    ]


def test_comment_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <!--
    <noscript>
    <textarea>
    <a href="injection">General Kenobi</a>
    <textarea>
    </noscript>
    -->
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "", "parent": "body", "type": "comment"}
    ]


def test_comment_in_noscript_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noscript>
    <textarea>
    <!--
    <a href="injection">General Kenobi</a>
    -->
    <textarea>
    </noscript>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "noscript", "parent": "textarea", "type": "comment"}
    ]


def test_attrname_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noembed>
    <input type=checkbox injection/>
    </noembed>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "non_exec_parent": "noembed",
            "tag": "input",
            "type": "attrname",
            "name": "injection",
            "events": set(),
            "special_attributes": {"type=checkbox"}
        }
    ]


def test_tagname_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <injection type=text name=username />
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "injection", "events": set()}
    ]


def test_partial_tagname_context():
    html = """<html>
    <head>
    <body>
    <noinjection>Hello there<noinjection>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "noinjection", "events": set()}
    ]


def test_attr_value_single_quote_and_event_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <a href='injection' onclick='location.href="index.html"';>General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "non_exec_parent": "",
            "tag": "a",
            "name": "href",
            "type": "attrval",
            "separator": "'",
            "events": {"onclick"},
            "special_attributes": {"href"}
        }
    ]


def test_multiple_contexts():
    html = """<html>
    <head><title>Hello injection</title>
    <body>
    <a href="injection">General Kenobi</a>
    <!-- injection -->
    <input type=checkbox injection />
    <noscript><b>injection</b></noscript>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {'non_exec_parent': 'title', 'parent': 'title', 'type': 'text'},
        {
            'events': set(),
            'name': 'href',
            'non_exec_parent': '',
            'separator': '"',
            'tag': 'a',
            'type': 'attrval',
            "special_attributes": {"href"}
        },
        {'non_exec_parent': '', 'parent': 'body', 'type': 'comment'},
        {
            'events': set(),
            'name': 'injection',
            'non_exec_parent': '',
            'tag': 'input',
            'type': 'attrname',
            "special_attributes": {"type=checkbox"}
        },
        {'non_exec_parent': 'noscript', 'parent': 'b', 'type': 'text'}
    ]


def test_similar_contexts():
    html = """<html>
    <body>
    <a href="injection">Hello there</a>
    <a href="injection2">General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "\"",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        }
    ]


def test_different_separator_contexts():
    html = """<html>
    <body>
    <a href="injection">Hello there</a>
    <a href='injection2'>General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "\"",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        },
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "'",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        }
    ]


def test_non_executable_context():
    html = """<html>
    <frameset>
        <frame src="top.html" />
        <frame src="bottom.html" />
    </frameset>
    injection
    </html>"""

    assert get_context_list(html, "injection") == []

    html = """<html>
    <frameset>
        <frame src="top.html" />
        <frame src="injection" />
    </frameset>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "type": "attrval",
            "name": "src",
            "tag": "frame",
            "events": set(),
            "separator": '"',
            "non_exec_parent": "frameset",
            "special_attributes": {"src"}
        }
    ]


def test_get_context_bug():
    # From a webpage that caused bugs
    html = """<!DOCTYPE html>
<html>

<head>
    <meta charset='utf-8'>
    <meta name="keywords" content="">
    <meta name="description" content="">
    <meta name="publisher" content=" ">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="msvalidate.01" content="" />
    <title>yolo GmbH</title>
    <link rel="canonical" href="https://shop.yolo.com">
    <link rel="alternate" href="https://shop.yolo.com" hreflang="de" />
    <base href="https://shop.yolo.com/">
    <link href="https://shop.yolo.com/favicon.ico" rel="shortcut icon">
</head>

<body>
    <div id="header">
        <div id="header_container">
            <div class="top_header">
                <a href='shop.php?SessID=id' id='logo' title='Startseite'>
                    <img src='benutzerdaten/400529/shop/layout/headline.png?1609952588' class='mobile_show'></a>
                <ul class='top_navi mobile_hide' style='width:100%'>
                    <li><a class='popup_toggle  ' href="index.php?page=AGB&amp;SessID=id">AGB</a></li>
                    <li><a class='popup_toggle  ' href="index.php?page=Shop&amp;SessID=id">Shop</a></li>
                </ul>
                <div class='top_navi_lang mobile_hide' style='display:none;'>
                    <div id='sprachauswahl'><span class='bold'>Sprache:&nbsp;&nbsp;</span>
                        <div class='placeholder'>
                            <a href="javascript:void(0);" class="click_toggle">deutsch</a>
                            <div class="click_div slide_down popup">
                                <a class="active" href='/ad.php?SessID=id&redirect_searchstring=zozo&do=changelanguage'>
                                    <img src='images/flaggen/de.png' target='_top' /><span>deutsch</span></a>
                                <a href='/ad.php?SessID=id&redirect_searchstring=zozo&do=changelanguage'>i
<img src='images/flaggen/en.png' target='_top' /><span>englisch</span></a>
                                <a href='/administration.php?SessID=id&redirect_searchstring=zozo&do=changelanguage'>
                                    <img src='images/flaggen/pl.png' target='_top' /><span>polnisch</span></a>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="clear"></div>
            </div>
        </div>
    </div>
    <div id='wrapper'>
        <div id="column_center" class="column_center content_container hide_both">

            <div class='loginTypes row flex-stretch'>
                <div class='col-12 col-lg-6'>
                    <form action=administration.php method=post class='styledForm'>
                        <input type=hidden name=SessID value=id>
                        <input type=hidden name=action value=login>
                        <input type=hidden name=redirect value=search3>
                        <input type=hidden name=redirect_searchstring value="zozo">
                    </form>
                </div>
                <div class='col-12 col-lg-6 flex-space-between'>
                    <div class='contentBlock'>
                        <div class='row header'>Neuer Kunde
                            <div class='headerIcon'><i id='openTextNewCustomer' class="fa fa-info-circle"></i></div>
                        </div>
                        <div class='row'>
                            <div class='col-full'>
<input onClick="javascript:location.href = 'n.php?SessID=id&redirect_searchstring=zozo';"
 class='large' type=button value='Plop'></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </div>
    </div>

    <div class='template_footer' style='max-width:none;'>
        <div class='footer-content'>
            <div class='template_footer_row'>
                <ul class='template_footer_container'>
                    <span class='template_footer_head'><div class='user_content'>Rechtliches</div></span>
                    <div id='sprachauswahl'><span class='bold'>Sprache:&nbsp;&nbsp;</span>
                        <div class='placeholder'>
                            <a href="javascript:void(0);" class="click_toggle">deutsch</a>
                            <div class="click_div slide_down popup">
                                <a class="active" href='/ad.php?SessID=id&redirect_searchstring=zozo&do=changelanguage'>
                                    <img src='images/flaggen/de.png' target='_top' /><span>deutsch</span></a>
                                <a href='/administration.php?SessID=id&redirect_searchstring=zozo&do=changelanguage'>
                                    <img src='images/flaggen/en.png' target='_top' /><span>englisch</span></a>
                                <a href='/administration.php?SessID=id&&redirect_searchstring=zozo&do=changelanguage'>
                                    <img src='images/flaggen/pl.png' target='_top' /><span>polnisch</span></a>
                            </div>
                        </div>
                    </div>
            </div>
            </ul>
        </div>
    </div>
    </div>
</body>

</html>"""
    assert get_context_list(html, "zozo") == [
        {
            'events': set(),
            'name': 'href',
            'non_exec_parent': '',
            'separator': "'",
            'special_attributes': {'href'},
            'tag': 'a',
            'type': 'attrval'
        },
        {
            'events': set(),
            'name': 'value',
            'non_exec_parent': '',
            'separator': '"',
            'special_attributes': {'type=hidden'},
            'tag': 'input',
            'type': 'attrval'
        },
        {
            'events': {'onclick'},
            'name': 'onclick',
            'non_exec_parent': '',
            'separator': '"',
            'special_attributes': {'type=button'},
            'tag': 'input',
            'type': 'attrval'
        }
    ]


def test_get_context_bug_2():
    html = """<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="lt" lang="lt">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Yolo.lt</title>
    <meta name="viewport" content="width=device-width, minimum-scale=1">
    <meta name="keywords" content="" />
    <meta name="description" content="Yolo.lt" />
    <meta name="SKYPE_TOOLBAR" content="SKYPE_TOOLBAR_PARSER_COMPATIBLE" />

    <meta property="og:title" content="Yolo.lt" />
    <meta property="og:site_name" content="Yolo.lt" />
    <meta property="og:description" content="Yolo.lt" />
    <meta property="og:type" content="article" />
    <meta property="og:locale" content="lt_LT" />
    <meta property="og:url" content="https://yolo/?q=zozo&dispatch=products.search%2F" />

    <link rel="shortcut icon" type="image/x-icon" href="https://yolo/styles/plop/images/favicon.ico" />
    <base href="https://yolo/" />

    <!--[if lt IE 9]>
<script type="text/javascript" src="https://yolo/js/pie-1.0b4/pie.js" defer="defer"></script>
<![endif]-->
    <!--[if lt IE 7]>
<link rel="stylesheet" href="https://yolo/styles/common/iefix_lt7.css" type="text/css" media="all" />
<link rel="stylesheet" href="https://yolo/styles/plop/css/iefix_lt7.css" type="text/css" media="all" />
<![endif]-->
    <!--[if gte IE 7]>
<link rel="stylesheet" href="https://yolo/styles/common/iefix_gte7.css" type="text/css" media="all" />
<link rel="stylesheet" href="https://yolo/styles/plop/css/iefix_gte7.css" type="text/css" media="all" />
<![endif]-->

    <script src="https://yolo/js/min/js_default_03648614_2359bbe0_b08282d9.php" type="text/javascript"></script>
    <link rel="alternate" hreflang="en" href="https://yolo/en/?q=zozo&dispatch=products.search%2F" />
    <link rel="alternate" hreflang="ru" href="https://yolo/ru/?q=zozo&dispatch=products.search%2F" />
    <link rel="alternate" hreflang="lv" href="https://yolo/lv/?q=zozo&dispatch=products.search%2F" />
    <link rel="alternate" hreflang="ee" href="https://yolo/ee/?q=zozo&dispatch=products.search%2F" />
</head>

<body id="template_body_col_1" class="body_col_1 body_col_1_lt b0 page-index main index" data-base-currency='EUR'>
    <div id="awholder">
        <div id="content-wrap">
            <div id="header-wrap" class="content-wrap">
                <div id="header" class="container_60">
                    <a id="logo" class="a0" href="https://yolo/" title="Elektroninė parduotuvė">
                        <picture>
                            <source type="image/webp" srcset="https://yolo/styles/plop/images/logo.png.webp">
                            <source type="image/png" srcset="https://yolo/styles/plop/images/logo.png">
                            <img src="https://yolo/styles/plop/images/logo.png"  alt="Yolo.lt" />
                        </picture>
                    </a>
                    <div id="shop-slogan" class="hidden-xs hidden-sm">
                    </div>

                    <div id="main-search" class="hidden-xs">
                        <form action="https://yolo/paieska" method="get" id="main_search_form">
                            <input id="main" class="fl input" type="text" name="q" value="zozo" placeholder="zozo" />
                            <div id="search-suggestion" class="search-suggestion dnn bg0 p5"></div>
                            <a id="main-search-submit" href="javascript:;"><span>Truc</span></a>
                        </form>
                    </div>

                </div>
            </div>
        </div>

    </div>
</body>

</html>"""
    assert get_context_list(html, "zozo") == [
        {
            'events': set(),
            'name': 'content',
            'non_exec_parent': '',
            'separator': '"',
            'tag': 'meta',
            'type': 'attrval'
        },
        {
            'events': set(),
            'name': 'href',
            'non_exec_parent': '',
            'separator': '"',
            'special_attributes': {'href', 'rel=alternate'},
            'tag': 'link',
            'type': 'attrval'
        },
        {
            'events': set(),
            'name': 'value',
            'non_exec_parent': '',
            'separator': '"',
            'special_attributes': {'type=text'},
            'tag': 'input',
            'type': 'attrval'
        },
        {
            'events': set(),
            'name': 'placeholder',
            'non_exec_parent': '',
            'separator': '"',
            'special_attributes': {'type=text'},
            'tag': 'input',
            'type': 'attrval'
        }
    ]


@respx.mock
def test_csp_detection():
    url = "http://perdu.com/"
    respx.get(url).mock(return_value=httpx.Response(200, headers={"Content-Type": "text/html"}))

    response = Response(httpx.get(url))
    assert not has_csp_header(response)
    assert not has_csp_meta(Html(response.content, url))

    url = "http://perdu.com/http_csp"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "blahblah;"
            }
        )
    )

    response = Response(httpx.get(url))
    assert has_csp_header(response)
    assert not has_csp_meta(Html(response.content, url))

    url = "http://perdu.com/meta_csp"

    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Type": "text/html"
            },
            text="""<html>
            <head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
            </head>
            <body>Hello there</body>
            </html>"""
        )
    )

    response = Response(httpx.get(url))
    assert not has_csp_header(response)
    assert has_csp_meta(Html(response.content, url))


@respx.mock
def test_valid_content_type():
    url = "http://perdu.com/"
    respx.get(url).mock(return_value=httpx.Response(200, headers={"Content-Type": "text/html"}))

    resp = httpx.get(url)
    page = Response(resp)
    assert valid_xss_content_type(page)

    url = "http://perdu.com/picture.png"
    respx.get(url).mock(return_value=httpx.Response(200, headers={"Content-Type": "image/png"}))

    resp = httpx.get(url)
    page = Response(resp)
    assert not valid_xss_content_type(page)


def test_payload_requirements():
    code = '<input type="hidden" value="injected"/>'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"type=hidden"}
    with pytest.raises(RuntimeError):
        # Requirement not met due to type being "hidden"
        meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"])

    code = '<input type="text" value="injected" style="imgroot" />'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"style", "type=text"}
    with pytest.raises(RuntimeError):
        # Requirement not met due to style being present
        meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"])

    code = '<input type="text" value="injected"/>'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"type=text"}
    # Requirement met as input type is not "hidden" and style is missing
    assert meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"]) == ""

    code = '<input value="injected"/>'
    context_list = get_context_list(code, "injected")
    # Requirement met as there is no special attributes to make our life harder
    assert "special_attributes" not in context_list[0]
    assert meet_requirements(["!style", "type!=hidden"], []) == ""


def test_find_separator():
    # Here the extraction of the separator between the attribute name and the attribute value containing the taint
    # may be annoying because the parameter named "content" may be found several time in the text, even with trailing =.
    code = '''<html>
<head>
<meta property="og:url" content="https://yolo.tld/default.asp?content=expanded&search_content=results&number=zzz" />
</head>
</html>'''
    assert find_separator(code, "zzz", "meta") == '"'
