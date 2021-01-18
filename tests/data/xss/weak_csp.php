<?php
header("Content-Security-Policy: default-src https: *; script-src https: 'unsafe-inline' 'unsafe-eval' *;img-src data: https:;font-src data: https:;style-src https: 'unsafe-inline' *;upgrade-insecure-requests;frame-ancestors 'self'; base-uri 'none'; frame-src mailto: *");
?><html>
<body>
<!-- Didn't read LOL -->
<?php echo $_GET["content"]; ?>
</body>
</html>