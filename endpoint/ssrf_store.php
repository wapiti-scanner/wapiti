<?php
error_reporting(-1);
ini_set('display_errors', 'On');

/* RewriteRule "^ssrf/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/?$" "/ssrf_store.php?session_id=$1&path_id=$2&hex_param=$3" */
$session_id = isset($_GET["session_id"]) ? $_GET["session_id"] : "";
$path_id = isset($_GET["path_id"]) ? $_GET["path_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($session_id) != 6) exit();
if (!ctype_alnum($session_id)) exit();
if (!ctype_digit($path_id)) exit();
if (!ctype_xdigit($hex_param)) exit();

include("functions.php");
$session_id = strtolower($session_id);

$time = time();
$i = 0;

$directory = "./ssrf_data/$session_id/$path_id/$hex_param/";
mkdir($directory, 0777, true);
(new DumpHTTPRequestToFile)->execute("$directory/$time-$ip.txt");

?>
