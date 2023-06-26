<?php
header_remove();
header("Content-Security-Policy: default-src *; script-src 'unsafe-inline'; 'unsafe-eval'; style-src 'unsafe-inline'; img-src *; connect-src *; foobar-src 'foobar'");
?>
<!DOCTYPE html>
<html>
    <head>
        <title>CSP Example</title>

    </head>
    <body>
        <p>Page with an CSP highly bypassable.</p>
    </body>
</html>

