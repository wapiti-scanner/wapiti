<?php
function jsfuckSanitize($str){
	// This will only let JSFuck pass
	$pattern="/<script>[\(\)\(\)\[\]\+!]+<\/script>/i";
	if(preg_match($pattern, $str)) return $str;
	else return preg_replace("/[<>\/]/i", '', $str);
}

if(!isset($_GET['group'])){
	$default_param="I_guess";
	$url = "advanced_xss.php?group=" . $default_param;
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
    <p>Hello user, there is something wrong with this page <?php echo (isset($_GET['group']) ? jsfuckSanitize($_GET['group']) : "wrong param !"); ?> </p>
	</ul>
</body>
</html>

