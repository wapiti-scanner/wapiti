<?php
header("location: /redirects/two_step_redirect_loop_1");
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
