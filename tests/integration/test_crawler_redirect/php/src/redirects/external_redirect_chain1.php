<?php
header("location: /redirects/external_redirect_chain2.php");
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
