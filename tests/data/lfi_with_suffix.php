<?php
// see https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d for exploitability
if (isset($_GET["f"])) {
    // set restrictive path that will block access to /etc, /var, etc
    set_include_path("/usr/lib/pear");
    // also prevent remote URLs
    if (strstr($_GET["f"], "http")) {
        echo "U r evil";
    } else {
        // finally, append a suffix so we should be safe, right?
        include($_GET["f"].".inc");
    }
}
?>