<html>
<body>
<?php
$msg = $_GET["msg"];
$bad_words = array("script", "onfocus", "onmouseover", "onload", "onerror", "onpageshow", "alert", "prompt", "confirm");
foreach ($bad_words as $bad_word) {
    if (stristr($msg, $bad_word)) {
        $msg = "Invalid content detected.";
    }
}

echo "<p>$msg</p>\n";
?>
</body>
</html>