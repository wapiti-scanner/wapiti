<?php
// Simulates a short delay redirect (500ms) that SHOULD be flagged as open redirect vulnerability
// Short delays (<3s) are too fast for users to cancel
?>
<html>
<head>
    <script type="text/javascript">
        setTimeout(() => {window.location.href="<?php echo htmlspecialchars($_GET['url'] ?? '/'); ?>";}, 500);
    </script>
</head>
<body>
    <div>Redirecting in 0.5 seconds...</div>
</body>
</html>
