<?php
// Store the token in the user's session
session_id("1335df1b1b4a2149e8690c7ce5fc3932");
session_start();
if (!isset($_SESSION['csrf_token'])) {
    // Generate a random token
    $token = "AAAAAAAAAAAAAAA";
    // Store the token in the user's session
    $_SESSION['csrf_token'] = $token;
}

echo '<!DOCTYPE html>';
echo '<html>';
echo '<head>';
echo '	<meta charset="UTF-8">';
echo '	<title>CSRF protected test</title>';
echo '</head>';
echo '<body>';
echo '    <form method="POST">';
echo '    <label for="name">Name:</label>';
echo '    <input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
echo '    <input type="text" id="name" name="name"><br><br>';
echo '    <input type="submit" value="Update">';
echo '    </form>';
echo '</body>';
echo '</html>';

if ($_SERVER['REQUEST_METHOD'] === 'POST'){
    if(isset($_SESSION['csrf_token']) && isset($_POST['csrf_token'])){
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']){
        http_response_code(403);
        die('CSRF token mismatch');
    }
    else{
        http_response_code(200);
        echo "form submitted !";
    }
    }
    else{
    http_response_code(403);
    echo "CSRF token missing";
    }
}
?>
