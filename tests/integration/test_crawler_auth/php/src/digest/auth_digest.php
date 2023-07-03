<?php
// Define the valid username and password for authentication
$valid_username = 'admin';
$valid_password = 'password';

// Check if the user has provided credentials
if (!isset($_SERVER['PHP_AUTH_DIGEST'])) {
    // Prompt the user to enter credentials
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Digest realm="Restricted Area", qop="auth", nonce="' . uniqid() . '", opaque="' . md5('Restricted Area') . '"');
    echo 'Authentication required.';
    exit;
}

// Parse the Digest authentication headers
$digest_data = [];
preg_match_all('/(\w+)=("([^"]+)"|([^\s,]+))/', $_SERVER['PHP_AUTH_DIGEST'], $matches, PREG_SET_ORDER);
foreach ($matches as $match) {
    $digest_data[$match[1]] = $match[3] ? $match[3] : $match[4];
}

// Verify the validity of the provided credentials
$digest_username = isset($digest_data['username']) ? $digest_data['username'] : '';
$digest_realm = isset($digest_data['realm']) ? $digest_data['realm'] : '';
$digest_nonce = isset($digest_data['nonce']) ? $digest_data['nonce'] : '';
$digest_uri = isset($digest_data['uri']) ? $digest_data['uri'] : '';
$digest_response = isset($digest_data['response']) ? $digest_data['response'] : '';
$digest_cnonce = isset($digest_data['cnonce']) ? $digest_data['cnonce'] : '';
$digest_nc = isset($digest_data['nc']) ? $digest_data['nc'] : '';
$digest_qop = isset($digest_data['qop']) ? $digest_data['qop'] : '';

$valid_response = md5(
    md5($digest_username . ':' . $digest_realm . ':' . $valid_password) .
    ':' . $digest_nonce . ':' . $digest_nc . ':' . $digest_cnonce . ':' . $digest_qop . ':' .
    md5($_SERVER['REQUEST_METHOD'] . ':' . $digest_uri)
);

if (!($digest_response === $valid_response)) {
    // Invalid credentials, deny access
    header('HTTP/1.1 401 Unauthorized');
    echo 'Invalid credentials.';
    exit;
}

// If the code execution reaches this point, the user is authenticated
// You can now proceed with displaying the protected content

echo 'Welcome, ' . $digest_username . '! You are authenticated.';
?>
