<?php
header("refresh: 0; url=/redirect_target.php?origin=header_refresh_redirect");
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
