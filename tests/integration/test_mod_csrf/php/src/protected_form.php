<?php
session_id("ldsu3ighl8der4ujghl3siur1fhgiu");
session_start();
if (!isset($_SESSION['csrf_token'])) {
    // Generate a random token
    $token = "d1db91e58e9f4710f1015bfcd12eea15df6663202d7bf5cb97d72a32044d8f35";
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
