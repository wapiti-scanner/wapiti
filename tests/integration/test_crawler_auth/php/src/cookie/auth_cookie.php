<?php
// Check if the user is already authenticated
if (isset($_COOKIE['token']) && $_COOKIE['token'] === '0123456789abcdefghijklmnopqrstuvwxyz') {
    // User is authenticated
    echo 'You are already logged in.';
}
else{
    echo 'You are not logged in, a cookie is required';
}
?>
