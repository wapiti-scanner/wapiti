<?php
error_reporting(-1);
ini_set('display_errors', 'On');

/* RewriteRule "^ssrf/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/?$" "/ssrf_store.php?rand_id=$1&req_id=$2&hex_param=$3" */
$rand_id = isset($_GET["rand_id"]) ? $_GET["rand_id"] : "";
$req_id = isset($_GET["req_id"]) ? $_GET["req_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($rand_id) != 6) exit();
if (!ctype_alnum($rand_id)) exit();
if (!ctype_digit($req_id)) exit();
if (!ctype_xdigit($hex_param)) exit();

include("functions.php");
$rand_id = strtolower($rand_id);

$time = time();
$i = 0;

$directory = "./ssrf_data/$rand_id/$req_id/$hex_param/";
mkdir($directory, 0777, true);
(new DumpHTTPRequestToFile)->execute("$directory/$time-$ip.txt");

?>
