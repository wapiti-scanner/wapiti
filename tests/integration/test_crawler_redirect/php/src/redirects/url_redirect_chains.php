<?php
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <a href="/redirects/redirect_chain_link.php?redirect_left=4">4 Redirects Chain Link</a>
    <a href="/redirects/redirect_chain_link.php?redirect_left=9">9 Redirects Chain Link</a>
    <a href="/redirects/redirect_chain_link.php?redirect_left=14">14 Redirects Chain Link</a>
  </body>
</html>
