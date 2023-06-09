<?php
if($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'PUT' ||  $_SERVER['REQUEST_METHOD'] === 'OPTIONS'){
    header_remove();
    header('Content-Type: text/html');
    header('Allow: ');
}else{
    http_response_code(405);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>empty options</title>
</head>
<body>
    <?php
        if($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'OPTIONS'){
            echo "<p>This is a page with an empty allow headers, thus, OPTIONS is supposed to find nothing</p>";
            echo "<p>PUT and GET are still accessible</p>";
        }elseif($_SERVER['REQUEST_METHOD'] === 'PUT'){
            echo "<p>This is a put method</p>";
        }else{
            echo "Method not allowed";
        }
    ?>
</body>
</html>
