<?php
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?> 
<!DOCTYPE html>
<html>
  <head>    
    <meta http-equiv="refresh" content="0;url=/redirects/infinite_meta_redirect.php"/>
  </head>
  <body>
  </body>
</html>
