<!DOCTYPE html>
<body>
<?php
    $tag = isset($_GET["tag"]) ? $_GET["tag"] : "p";
    echo "<$tag>Hello there</$tag>"
?>
</body>
</html>