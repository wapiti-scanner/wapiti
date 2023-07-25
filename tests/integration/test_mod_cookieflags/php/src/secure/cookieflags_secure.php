<?php
	// Set a cookie named "my_cookie" with the value "example_value"
	setcookie("secure_cookie", "example_value", 0, "/secure", "", true, true );
?>
<!DOCTYPE html>
<html>
	<head>
		<title>Set Cookie Example</title>
	</head>
	<body>
		<p>Cookie set successfully.</p>
	</body>
</html>