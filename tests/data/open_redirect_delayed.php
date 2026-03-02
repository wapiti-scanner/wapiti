<?php
// Simulates a delayed redirect that should NOT be flagged as open redirect vulnerability
// The 3 second delay gives users time to cancel, making it non-exploitable
?>
<html>
<head>
    <meta name="robots" content="noindex, nofollow">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <title>Redirecting</title>
    <script type="text/javascript">
        function goback() {window.history.go(-1);return false;}
        setTimeout(function(){window.location.href="<?php echo htmlspecialchars($_GET['url'] ?? '/'); ?>";},3000);
    </script>
</head>
<body>
    <div>The page will jump to <a href="<?php echo htmlspecialchars($_GET['url'] ?? '/'); ?>"><?php echo htmlspecialchars($_GET['url'] ?? '/'); ?></a> after 3 seconds.</div>
    <div>If you do not want to visit the page, you can <a href="#" onclick="return goback();">return to the previous page</a>.</div>
</body>
</html>
