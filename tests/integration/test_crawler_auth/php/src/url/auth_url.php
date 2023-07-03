<?php
session_id("1335df1b1b4a213");
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST'){
// Define valid username and password
$validUsername = 'admin';
$validPassword = 'password';

// Get the username and password from the URL parameters
$username = $_POST['username'];
$password = $_POST['password'];

// Validate the credentials
if ($username === $validUsername && $password === $validPassword) {
    // Authentication successful
    $_SESSION['authenticated_url'] = true;
    header_remove();
    header('Location: index.php');
    exit;
} else {
    // Authentication failed
    http_response_code(401);
    echo "Invalid credentials. Access denied.\n";
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Login Form</title>
</head>

<body>
    <h1>Login Form</h1>

    <form method="POST" action="">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>

        <button type="submit">Submit</button>
    </form>
    </body>

</html>
