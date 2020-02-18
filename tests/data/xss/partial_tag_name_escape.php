<!DOCTYPE html>
<body>
<?php
    $importance = isset($_GET["importance"]) ? $_GET["importance"] : "3";
    echo "<h$importance>Hello there</h$importance>"
?>
</body>
</html>