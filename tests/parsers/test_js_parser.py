import responses
import requests

from wapitiCore.net.crawler import Page
from wapitiCore.net.lamejs import LameJs


@responses.activate
def test_js_parser():
    with open("tests/data/js_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url)
        page = Page(resp)

        assert set(page.extra_urls) == {
            "http://perdu.com/onload.html",
            "http://perdu.com/popup.html",
            "http://perdu.com/redir.html",
            "http://perdu.com/concat.html",
            "http://perdu.com/concat.html?var=value",
            "http://perdu.com/link.html",
        }


def test_js_false_positives():
    scripts = [
        # from https://public-firing-range.appspot.com/remoteinclude/script_hash.html
        """
        var target = location.hash.substr(1);
        var head = document.getElementsByTagName('head')[0];
        var script = document.createElement('script');
        script.type = 'text/javascript';
        script.src = target;
        head.appendChild(script);
        """,
        """
        function yolo() {
          u='http://www.website.com/page.php?uid=1';
          t='Hi there';
          window.open('http://www.facebook.com/sharer.php?u='+encodeURIComponent(u)+'&t='+encodeURIComponent(t),'sharer','toolbar=0,status=0,width=626,height=436');
          return false;
        }""",

        """
        function openWindow(url, w, h, sb) {
          var options = "width=" + w + ",height=" + h + ",";
          options += "resizable=no, status=no,";
          options += "menubar=no, toolbar=no, location=no, directories=no,";
          options += "scrollbars=" + sb;
          var newWin = window.open(url, 'newWin', options);
        }
    
        function openBrWindow(theURL,winName,features) { //v2.0
        window.open(theURL,winName,features);
        }""",
        """window.location.href = this.value;"""
    ]
    for script in scripts:
        lame_js = LameJs(script)
        assert not lame_js.get_links()


def test_html_comments():
    lame_js = LameJs("""<!--
    window.location = "http://perdu.com/";
    -->
    """)
    assert lame_js.get_links() == ["http://perdu.com/"]
