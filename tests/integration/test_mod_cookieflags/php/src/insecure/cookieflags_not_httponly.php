<?php
	// Set a cookie named "my_cookie" with the value "example_value"
	setcookie("not_httponly_cookie", "example_value", 0, "/insecure", "", true, false);
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