<?php
error_reporting(-1);
ini_set('display_errors', 'On');

include("functions.php");

$session_id = isset($_GET["session_id"]) ? $_GET["session_id"] : "";
if (strlen($session_id) ==6 && ctype_alnum($session_id))
{
    // this is the global final array
    $by_path_id = array();
    $directory = "./xxe_data/$session_id";

    foreach (glob("$directory/*/*/*.txt") as $filename) {
        $parts = explode("/", $filename);
        list($time, $payload_num, $ip) = explode("-", basename($filename, ".txt"));
        $path_id = $parts[3];
        $hex_param = $parts[4];
        $url = site_url() . substr($filename, 2);
        $size = filesize($filename);

        if (!array_key_exists($path_id, $by_path_id)) {
            $by_path_id[$path_id] = array();
        }

        if (!array_key_exists($hex_param, $by_path_id[$path_id])) {
            $by_path_id[$path_id][$hex_param] = array();
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
            case 3:
                $payload = "javalin";
                break;
            case 4:
                $payload = "javawin";
                break;
            default:
                $payload = "unknown";
        }

        $by_path_id[$path_id][$hex_param][] = array(
            "date" => date('c', $time),
            "url" => $url,
            "ip" => $ip,
            "size" => $size,
            "payload" => $payload
        );
    }
    echo json_encode($by_path_id, JSON_PRETTY_PRINT);
}

?>
