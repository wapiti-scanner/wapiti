<?php
session_id("8f6s47ef68wse4f38esfsfew864fqdez");
session_start();
if($_SERVER['REQUEST_METHOD'] === 'POST'){
    http_response_code(200);
    echo "form submitted !";
}
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>CSRF unprotected test</title>
</head>
<body>
    <form method="post">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name"><br><br>
    <input type="submit" value="Update">
    </form>
</body>
</html>

