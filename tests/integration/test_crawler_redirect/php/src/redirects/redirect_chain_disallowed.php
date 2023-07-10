<?php
header("location: /redirect_target.php?origin=redirect_chain_disallowed");
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
