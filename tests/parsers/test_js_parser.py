from wapitiCore.parsers.html_parser import Html, extract_js_redirections


def test_js_parser():
    with open("tests/data/js_links.html") as fd:
        url = "http://perdu.com/"
        page = Html(fd.read(), url)

        assert {
           "http://perdu.com/link.html",
           "http://perdu.com/onload.html",
           "http://perdu.com/popup.html",
           "http://perdu.com/redir.html",
        } == set(page.js_redirections)


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
          window.open(
              'http://www.facebook.com/sharer.php?u='+encodeURIComponent(u)+'&t='+encodeURIComponent(t),
              'sharer','toolbar=0,status=0,width=626,height=436'
          );
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
        """window.location.href = this.value;""",
        # Attempt to concat strings was removed
        """window.open("http://perdu.com/" + "abcd.html");""",
        """document.href="http://httpbin.org/" + "test";"""
    ]
    for script in scripts:
        assert not extract_js_redirections(script)


def test_html_comments():
    page = Html(
        """<!-- window.location = "http://perdu.com/secret"; -->""",
        "http://perdu.com/"
    )

    assert page.js_redirections == ["http://perdu.com/secret"]
