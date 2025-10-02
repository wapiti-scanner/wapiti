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


def test_delayed_redirect_filtering():
    """Test that setTimeout-wrapped redirects with 3+ second delays are filtered out.

    Issue #512: Delayed redirects are not exploitable as users have time to cancel.
    """
    # Delayed redirect - should NOT be extracted
    script_delayed_3s = """
        setTimeout(function(){window.location.href="https://evil.com/";}, 3000);
    """
    assert not extract_js_redirections(script_delayed_3s)

    # Delayed redirect with arrow function - should NOT be extracted
    script_delayed_5s = """
        setTimeout(() => {location.href="https://evil.com/";}, 5000);
    """
    assert not extract_js_redirections(script_delayed_5s)

    # Short delay redirect - SHOULD be extracted (too fast to cancel)
    script_short_delay = """
        setTimeout(function(){window.location.href="https://evil.com/";}, 500);
    """
    assert extract_js_redirections(script_short_delay) == ["https://evil.com/"]

    # Immediate redirect - SHOULD be extracted
    script_immediate = """
        window.location.href = "https://evil.com/";
    """
    assert extract_js_redirections(script_immediate) == ["https://evil.com/"]

    # Multiple redirects with mixed delays
    script_mixed = """
        window.location.href = "https://immediate.com/";
        setTimeout(function(){location="https://delayed.com/";}, 3000);
        setTimeout(() => {location.href="https://short.com/";}, 100);
    """
    result = extract_js_redirections(script_mixed)
    assert "https://immediate.com/" in result
    assert "https://short.com/" in result
    assert "https://delayed.com/" not in result


def test_real_world_delayed_redirect():
    """Test the exact pattern from issue #512."""
    html_content = """
    <html>
    <head>
        <script type="text/javascript">
            function goback() {window.history.go(-1);return false;}
            setTimeout(function(){window.location.href="https://openbugbounty.org/";},3000);
        </script>
    </head>
    <body>
        The page will jump to <a href="https://openbugbounty.org/">https://openbugbounty.org/</a> after 3 seconds.
    </body>
    </html>
    """
    # The setTimeout-wrapped redirect should NOT be extracted
    assert not extract_js_redirections(html_content)


def test_nested_and_complex_settimeout():
    """Test edge cases with nested setTimeout and complex patterns."""
    # Nested setTimeout
    script_nested = """
        setTimeout(function(){
            setTimeout(function(){location.href="https://nested.com/";}, 4000);
        }, 1000);
    """
    # Outer timeout is 1000ms (short), but inner is 4000ms (long)
    # The redirect itself is in the 4000ms timeout, so should be filtered
    result = extract_js_redirections(script_nested)
    assert "https://nested.com/" not in result

    # setTimeout with variable delay (non-constant) - should be extracted (safe default)
    script_variable = """
        var delay = 5000;
        setTimeout(function(){location.href="https://variable.com/";}, delay);
    """
    # Can't parse variable delays, so assume not delayed
    result = extract_js_redirections(script_variable)
    # This should be extracted because we can't determine the delay
    assert "https://variable.com/" in result
