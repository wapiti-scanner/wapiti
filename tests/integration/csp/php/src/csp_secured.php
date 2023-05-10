<?php
header("Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; frame-src 'none'; object-src 'none'; media-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; reflected-xss block; report-uri /csp-report-endpoint/");
?>
<!DOCTYPE html>
<html>
    <head>
        <title>CSP Example</title>
    </head>
    <body>
        <p>Page with an CSP highly secured.</p>
    </body>
</html>

