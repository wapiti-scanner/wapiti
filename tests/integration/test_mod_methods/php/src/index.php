<?php
if($_SERVER['REQUEST_METHOD'] === 'GET'){
    echo "<!DOCTYPE html>";
    echo "<html>\n";
    echo "<head>\n";
    echo "    <title>Methods</title>\n";
    echo "</head>\n";
    echo "<body>\n";
    echo "    <ul>\n";
    echo "        <li>first page with different return with DELETE <a href=\"different_delete_return.php\"></a>link 1</li>\n";
    echo "        <li>second page with different return and empty OPTIONS <a href=\"empty_options.php\"></a>link 2</li>\n";
    echo "        <li>third page with same return <a href=\"same_return.php\"></a>link 3</li>\n";
    echo "    </ul>\n";
    echo "</body>\n";
    echo "</html>\n";
}elseif($_SERVER['REQUEST_METHOD'] === 'OPTIONS'){
    header('Allow: GET');
    header('Content-lenght: 0');
    header('Content-Type: text/plain');
}else{
    http_response_code(405); // Method Not Allowed
    header('Content-Type: text/html');
    echo "<h1>Method not allowed.</h1>\n";
}
?>
