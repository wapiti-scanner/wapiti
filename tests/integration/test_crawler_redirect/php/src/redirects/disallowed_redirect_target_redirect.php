<?php
header('Location: /disallow_redirect_target.php', true, 301);
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
exit;
?>
