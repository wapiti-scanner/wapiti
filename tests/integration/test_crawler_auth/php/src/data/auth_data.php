<?php
session_id("1335df1b1b4a214");
session_start();
// Define valid username and password
$validUsername = 'admin';
$validPassword = 'password';

// Get the username and password from the POST data
$username = $_POST['us3rn4mexyz'] ?? '';
$password = $_POST['p455w0rd'] ?? '';
// Validate the credentials
if ($username === $validUsername && $password === $validPassword) {
    // Authentication successful
    $_SESSION['authenticated_data'] = true;
    header_remove();
    header('Location: index.php');
    exit;
} else {
    // Authentication failed
    http_response_code(401);
    echo 'Invalid credentials. Access denied.';
}
?>
