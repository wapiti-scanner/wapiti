<?php
// Generate a random token
$token = bin2hex(random_bytes(32));
// Store the token in the user's session
session_start();
$_SESSION['csrf_token'] = $token;
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>CSRF protected test</title>
</head>
<body>
    <form action="csrf_verify.php" method="post">
    <label for="name">Name:</label>
    <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
    <input type="text" id="name" name="name"><br><br>
    <input type="submit" value="Update">
    </form>
</body>
</html>

