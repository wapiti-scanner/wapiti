<?php

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Process the form data here
    if($_POST['username']=="admin" && $_POST['password']="123456"){
    // Set the HTTP response headers
    header('HTTP/1.1 200 OK');
    header('Content-Type: text/html');
    header('Custom-Header: Custom-Value');
    // Output the response body
    echo 'Your form has been submitted successfully.';
    }
    else{
        // The login failed, return a 401 Unauthorized response
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Basic realm="Restricted Area"');
        echo 'Invalid username or password.';
    }
    exit; // Exit the script to prevent further output
}
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8"/>
	<title>Bruteforce Login form</title>
</head>
<body>
	<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
    <div>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username">
    </div>
    <div>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password">
    </div>
    <div>
        <button type="submit">Log in</button>
    </div>
</form>
</body>
</html>