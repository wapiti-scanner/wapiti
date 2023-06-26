<?php
session_id("1335df1b1b4a2149e8690c7ce5");
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

