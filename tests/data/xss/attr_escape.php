<html>
<body>
<?php $state = isset($_GET["state"]) ? $_GET["state"] : ""; ?>
Choose car brand: <input type="checkbox" name="brand" value="Honda" <?=$state?> ><br />
</body>
</html>