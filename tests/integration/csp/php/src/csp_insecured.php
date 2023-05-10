<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-src 'self'; object-src 'self'; media-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; reflected-xss block; report-uri /csp-report-endpoint/");
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

