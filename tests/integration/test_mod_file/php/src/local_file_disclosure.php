<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file);
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>File Injections</title>
    </head>
    <body>
        <p>Here you can use the file attribute to include files</p>
    </body>
</html>

