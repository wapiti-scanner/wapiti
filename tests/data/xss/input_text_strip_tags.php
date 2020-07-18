<?php
    $uid = isset($_GET["uid"]) ? strip_tags($_GET["uid"]) : "";

?>
<!DOCTYPE html>
<body>
<form>
<input type="text" name="uid" value="<?=$uid ?>" />
</form>
</body>
</html>