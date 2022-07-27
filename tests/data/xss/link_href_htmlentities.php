<?php
    $url = isset($_GET["url"]) ? htmlentities($_GET["url"]) : "";

?>
<!DOCTYPE html>
<body>
<form>
<a href="<?=$url ?>">clickme</a>
</form>
</body>
</html>