<?php
if(isset($_GET['file'])){
    if(!file_exists($_GET['file']) && strpos($_GET['file'], "php:") !== false){    
        include($_GET['file']);
    }
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>File Injections</title>
    </head>
    <body>
        <p>Here you can use the file attribute to show source of files</p>
        <p>path to local files are sanitized, you can still inject remote PHP payload</p>
    </body>
</html>

