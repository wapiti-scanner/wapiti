<!DOCTYPE html>

<html>

<head>

	<title>Set Cookie Example</title>

</head>

<body>

	<?php

		// Set a cookie named "my_cookie" with the value "example_value"

		setcookie("my_cookie", "example_value", time()+3600, "/", "localhost"; true; true );

	?>

	<p>Cookie set successfully.</p>

</body>

</html>