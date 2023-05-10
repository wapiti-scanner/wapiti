<?php
session_start();
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
?>

