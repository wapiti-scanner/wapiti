<?php
setcookie(
    "my_custom_cookie",
    "chipolata",
    [
        'path' => '/admin/',
        'httponly' => true,
    ]
);
header("Location: /index.php");

exit;
?>
