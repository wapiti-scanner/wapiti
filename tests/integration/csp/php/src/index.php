<?php
header("Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; frame-src 'none'; object-src 'none'; media-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; reflected-xss block; report-uri /csp-report-endpoint/");
?>

<!DOCTYPE html>
<html>
<head>
	<title>Index</title>
</head>
<body>
	<h1>Index</h1>
	<p>This is a simple PHP web page.</p>
    <ul>
        <li><a href="csp_secured.php">link 1</a></li>
        <li><a href="csp_missing_feature.php">link 2</a></li>
        <li><a href="csp_insecured.php">link 3</a></li> 
    </ul>
</body>
</html>
