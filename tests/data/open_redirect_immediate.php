<?php
// Simulates an immediate redirect that SHOULD be flagged as open redirect vulnerability
?>
<html>
<head>
    <script type="text/javascript">
        window.location.href="<?php echo htmlspecialchars($_GET['url'] ?? '/'); ?>";
    </script>
</head>
<body>
    <div>Redirecting immediately...</div>
</body>
</html>
