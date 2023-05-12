<?php
header_remove();
header("Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval' 'self' data: https://www.google.com http://www.google-analytics.com/gtm/js  https://*.gstatic.com/feedback/ https://ajax.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.google.com; default-src 'self' * 127.0.0.1 https://[2a00:79e0:1b:2:b466:5fd9:dc72:f00e]/foobar; img-src https: data:; child-src data:; foobar-src 'foobar'; report-uri http://csp.example.com;")
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

