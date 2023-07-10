<?php
header("location: /");
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
<a href="/redirects/redirect_content_link">Redirect content link</a>
