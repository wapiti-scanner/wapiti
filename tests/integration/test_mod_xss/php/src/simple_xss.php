<?php
if(!isset($_GET['group'])){
	$default_param="I_guess";
	$url = "simple_xss.php?group=" . $default_param;
	header("Location: " . $url);
}
?>
<!DOCTYPE html>
<html>
<head>
	<title>Welcome VulnWebsite</title>
</head>
<body>
	<p>This is a simple page.</p>
	<ul>
    <p>Hello user, there is something wrong with this page <?php echo (isset($_GET['group']) ? $_GET['group'] : "wrong param !"); ?> </p>
	</ul>
</body>
</html>

