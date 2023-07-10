<?php
header('Location: /redirect_target.php?origin=disallowed_redirect', true, 301);
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
exit;
?>
