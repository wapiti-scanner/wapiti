<?php
session_id("1335df1b1b4a213");
session_start();

if (!isset($_SESSION['authenticated_url']) || $_SESSION['authenticated_url'] !== true) {
    // User is not authenticated, redirect to login page
    http_response_code(401);
    exit;
}else{
    // User is authenticated, display the page content
    http_response_code(200);
    echo "<button>disconnect</button>";
}
?>
