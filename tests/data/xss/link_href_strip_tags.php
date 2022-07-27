<?php
    $url = isset($_GET["url"]) ? strip_tags($_GET["url"]) : "";

?>
<!DOCTYPE html>
<body>
<form>
<a href="something?<?=$url ?>">clickme</a>
</form>
</body>
</html>