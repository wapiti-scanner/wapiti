<?php
error_reporting(-1);
ini_set('display_errors', 'On');

include("functions.php");

$id = isset($_GET["id"]) ? $_GET["id"] : "";
if (strlen($id) ==6 && ctype_alnum($id))
{
    // this is the global final array
    $by_req_id = array();
    $directory = "./xxe_data/$id";

    foreach (glob("$directory/*/*/*.txt") as $filename) {
        $parts = explode("/", $filename);
        list($time, $payload_num, $ip) = explode("-", basename($filename, ".txt"));
        $req_id = $parts[3];
        $hex_param = $parts[4];
        $url = site_url() . substr($filename, 2);
        $size = filesize($filename);

        if (!array_key_exists($req_id, $by_req_id)) {
            $by_req_id[$req_id] = array();
        }

        if (!array_key_exists($hex_param, $by_req_id[$req_id])) {
            $by_req_id[$req_id][$hex_param] = array();
        }

        $payload_num = intval($payload_num);
        switch($payload_num) {
            case 0:
                $payload = "linux2";
                break;
            case 1:
                $payload = "linux";
                break;
            case 2:
                $payload = "windows";
                break;
            default:
                $payload = "unknown";
        }

        $by_req_id[$req_id][$hex_param][] = array(
            "date" => date('c', $time),
            "url" => $url,
            "ip" => $ip,
            "size" => $size,
            "payload" => $payload
        );
    }
    echo json_encode($by_req_id, JSON_PRETTY_PRINT);
}

?>
