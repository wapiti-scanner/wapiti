<?php
session_id("1335df1b1b4a214");
session_start();

if (!isset($_SESSION['authenticated_data']) || $_SESSION['authenticated_data'] !== true) {
    // User is not authenticated, redirect to login page
    http_response_code(401);
    exit;
}
else{
    // User is authenticated, display the page content
    http_response_code(200);
    echo "<!DOCTYPE html>";
    echo "<html lang=\"en\">";
    echo "<head>";
    echo "    <title>Logged in !</title>";
    echo "</head>";
    echo "<body>";
    echo "<button>disconnect</button>";
    echo "</body>";
    echo "</html>";
}
?>
