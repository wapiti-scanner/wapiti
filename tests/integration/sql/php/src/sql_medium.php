<?php
if(isset($_GET['query']) && (preg_match("/.*AND.*/i", $_GET['query']) || !preg_match("/.*[\"\)\(=]+.*/i", $_GET['query']))){
    // regexes let every normal requests pass (without special chars such as "()=) or requests have 'AND' in it pass
    echo !preg_match("/.*[\%]+.*/i", $_GET['query']) ? 1 : 0;
    $db = new SQLite3('../target.sqlite', SQLITE3_OPEN_READWRITE); 
    echo $db->querySingle('SELECT mail FROM users WHERE name="' . $_GET['query'] . '";') . "\n";
}
else{
    header("Location: ./sql_medium.php?query=Linda");
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
