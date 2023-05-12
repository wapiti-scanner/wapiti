<?php
header_remove();
header("Content-Security-Policy: default-src 'none'  ; frame-ancestors 'self' ; base-uri 'self' ; block-all-mixed-content ;")
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

