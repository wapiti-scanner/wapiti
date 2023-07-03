<?php
// Define the username and password for authentication
$valid_username = 'admin';
$valid_password = 'password';

// Check if the user has provided credentials
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW'])) {
    // Prompt the user to enter credentials
    header('WWW-Authenticate: Basic realm="Restricted Area"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Authentication required.';
    exit;
}

// Check if the provided credentials are valid
$user = $_SERVER['PHP_AUTH_USER'];
$pass = $_SERVER['PHP_AUTH_PW'];
$is_authenticated = ($user === $valid_username) && ($pass === $valid_password);

if (!$is_authenticated) {
    // Invalid credentials, deny access
    header('HTTP/1.0 401 Unauthorized');
    echo 'Invalid credentials.';
    exit;
}

// If the code execution reaches this point, the user is authenticated
// You can now proceed with displaying the protected content

echo 'Welcome, ' . $user . '! You are authenticated.';
?>
