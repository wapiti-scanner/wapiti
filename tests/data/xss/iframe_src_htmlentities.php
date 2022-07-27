<?php
    $url = isset($_GET["url"]) ? htmlentities($_GET["url"]) : "about:blank";

?>
<!DOCTYPE html>
<body>

<iframe src="<?=$url ?>"></iframe>
</body>
</html>