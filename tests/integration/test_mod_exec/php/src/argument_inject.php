<?php
if(isset($_GET['args'])){
    echo system("ls " . $_GET['args']);
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>CMD Injections</title>
    </head>

    <body>
        <p>Here you can use the args attribute to inject commands</p>
</body>
</html>
