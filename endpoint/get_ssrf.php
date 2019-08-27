<?php
error_reporting(-1);
ini_set('display_errors', 'On');

include("functions.php");

$id = isset($_GET["id"]) ? $_GET["id"] : "";
if (strlen($id) == 6 && ctype_alnum($id))
{
    // this is the global final array
    $by_req_id = array();
    $directory = "./ssrf_data/$id";

    foreach (glob("$directory/*/*/*.txt") as $filename) {
        $parts = explode("/", $filename);
        $time_and_ip = basename($filename, ".txt");
        list($time, $ip) = explode("-", $time_and_ip);
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

        $handle = @fopen($filename, "r");
        $method = "";
        if ($handle) {
            if (($buffer = fgets($handle, 10)) !== false) {
                list($method, $rest) = explode(" ", $buffer, 2);
            }
            fclose($handle);
        }

        $by_req_id[$req_id][$hex_param][] = array(
            "date" => date('c', $time),
            "url" => $url,
            "ip" => $ip,
            "size" => $size,
            "method" => $method
        );
    }
    echo json_encode($by_req_id, JSON_PRETTY_PRINT);
    // var_dump($by_req_id);
}

?>
