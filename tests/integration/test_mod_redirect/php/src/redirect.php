<?php
if(isset($_GET['link']) && preg_match('/^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w.-]*)*\/?$/', $_GET['link'] )){
    header_remove();
    header( 'Location:' . $_GET['link']);
}
else{
 echo '<!DOCTYPE html>';
 echo '<html lang="en">';
 echo '<head>';
 echo '    <meta charset="UTF-8"/>';
 echo '    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>';
 echo '    <title>Redirect</title>';
 echo '</head>';
 echo '<body>';
 echo '   <p>Invalid parameter or url</p> ';
 echo '</body>';
 echo '</html>';
}
?>
