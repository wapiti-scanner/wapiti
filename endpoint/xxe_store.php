<?php
/* RewriteRule "^xoxo/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/([0-9]+)/(.*)$" "/xxe_store.php?rand_id=$1&req_id=$2&hex_param=$3&payload=$4&data=$5" */

$rand_id = isset($_GET["rand_id"]) ? $_GET["rand_id"] : "";
$req_id = isset($_GET["req_id"]) ? $_GET["req_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$payload_num = isset($_GET["payload"]) ? $_GET["payload"] : "";
$data = isset($_GET["data"]) ? $_GET["data"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($rand_id) != 6) exit();
if (!ctype_alnum($rand_id)) exit();
if (!ctype_digit($req_id)) exit();
if (!ctype_xdigit($hex_param)) exit();
if (!ctype_digit($payload_num)) exit();
if (!strlen($data)) exit();
$data = base64_decode($data);

$time = time();
$directory = "./xxe_data/$rand_id/$req_id/$hex_param/";
mkdir($directory, 0777, true);
file_put_contents("$directory/$time-$payload_num-$ip.txt", $data, FILE_APPEND);
?>
