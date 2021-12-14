<?php

function get_url() {
    if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')   
         $url = "https://";   
    else  
         $url = "http://";   
    // Append the host(domain name, ip) to the URL.   
    $url.= $_SERVER["HTTP_HOST"];   
    
    // Append the requested resource location to the URL   
    $url.= $_SERVER["REQUEST_URI"];
    return $url;
}

$dump = array(
    "headers" => array(),
    "url" => get_url(),
    "args" => array(),
    "form" => array(),
    "files" => array()
);

if ($_SERVER["CONTENT_TYPE"] == "application/json") {
    $json = file_get_contents('php://input');
    $dump["data"] = $json;
    $dump["json"] = json_decode($json);
}

$headers = apache_request_headers();
foreach ($headers as $header => $value) {
    $dump["headers"][$header] = $value;
}

foreach ($_GET as $key => $value) {
    $dump["args"][$key] = $value;
}

foreach ($_POST as $key => $value) {
    $dump["form"][$key] = $value;
}

foreach ($_FILES as $key => $value) {
    $dump["files"][$key] = file_get_contents($value["tmp_name"]);
}

echo json_encode($dump, JSON_PRETTY_PRINT);

?>
