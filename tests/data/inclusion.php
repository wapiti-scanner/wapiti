<?php
if (isset($_GET["f"])) {
    if (strstr($_GET["f"], "services")) {
        echo "Network services, Internet style";
    }
}
if (isset($_GET["yolo"]) && $_GET["yolo"] == "warn") {
    echo "Failed opening required blahblahblah";
}
?>
false positive:
root:x:0:0:root:/root:/bin/bash
