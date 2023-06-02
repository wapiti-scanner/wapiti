<?php
if(isset($_GET['query'])){
    //let every request pass
    $db = new SQLite3('../target.sqlite', SQLITE3_OPEN_READWRITE);
    echo $db->querySingle('SELECT mail FROM users WHERE name="' . $_GET['query'] . '";') . "\n";
}
else{
    header("Location: ./sql_easy.php?query=Linda");
}
?>
<!DOCTYPE html>
<html>
<head>
    <h1>SQL vulns</h1>
</head>
<body>
    <p>You can query the DB with the name of the person, it will return its mail</p>
</body>
</html>
