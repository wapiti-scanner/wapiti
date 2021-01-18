<?php
header("content-security-policy: default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none';");
?><html>
<body>
<!-- No filters but an annoying CSP -->
<?php echo $_GET["content"]; ?>
</body>
</html>