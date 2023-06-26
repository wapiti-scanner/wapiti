<?php
$allowedDirectory="/var/www/html";
if(isset($_GET['file'])){
    $filePath=realpath($allowedDirectory . '/' . $_GET['file']);
    if($filePath && strpos($filePath, $allowedDirectory) === 0 && is_file($filePath)){
        $handle=fopen($filePath, 'r');
        echo fread($handle, filesize($filePath));
    }
    else{
        echo "non";
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
        <p>path to local files are sanitized, you can still view source code of the website</p>
    </body>
</html>

