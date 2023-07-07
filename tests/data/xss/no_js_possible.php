<html>
<body>
<?php

function stristr_multiple($haystack, $needles) {
    foreach ($needles as $needle) {
        $result = stristr($haystack, $needle);
        if ($result !== false) {
            return $result;
        }
    }
    return false;
}


function filterHTML($html) {
    // Define the regular expression pattern to match event attributes
    $pattern = '/(?:\s+|\/)on\w+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^>\s]*)/i';

    // Remove event attributes using regular expressions
    $filteredHTML = preg_replace($pattern, '', $html);

    return $filteredHTML;
}

$name = isset($_GET["name"]) ? $_GET["name"] : "anonymous coward";

$name = filterHTML($name);
$patterns = array("script", "object");
if (stristr_multiple($name, $patterns)) {
    // Look mah, uber-31337 xss filtering
    $name = "anonymous hacker";
}
echo $name;
?>

