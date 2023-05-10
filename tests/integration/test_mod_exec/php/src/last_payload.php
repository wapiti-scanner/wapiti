<?php
if(isset($_GET['abc'])){

    if(strpos($_GET['abc'], '&') !== false && strpos($_GET['abc'], ';') === false){
        echo system("echo foo &" . $_GET['abc'] . "& echo done");
    }
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>CMD Injections</title>
    </head>

    <body>
        <p>Here you can use the abc attribute to inject commands</p>
</body>
</html>
