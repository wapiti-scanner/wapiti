<?php
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="refresh" content="0;url=/redirect_target.php?origin=meta_redirect_1"/>
  </head>
  <body>    
  </body>
</html>
