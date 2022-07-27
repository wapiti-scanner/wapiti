<?php
//urls are not allowed on redirect
if (isset($_GET["url"]) && filter_var($_GET['url'], FILTER_VALIDATE_URL) === false)
    $url = $_GET["url"];
else
    $url = "/";
header("location: ".$url);
echo "plop";
?>
