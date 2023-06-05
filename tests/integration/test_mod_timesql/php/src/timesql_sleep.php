<?php
if(isset($_GET['query'])){
    //let every request pass
    $host=getenv('MYSQL_HOST');
    $user=getenv('MYSQL_USER');
    $password=getenv('MYSQL_PASSWORD');
    $db=getenv('MYSQL_DATABASE');

    $conn = new mysqli($host, $user, $password, $db);
    if($conn->connect_error){
    echo 'Connection failed' . $conn->connect_error;
    }else{
    echo "Connection succeed\n";
    }
    $rows =  $conn->query('SELECT mail FROM users WHERE name="' . $_GET['query'] . '";')->fetch_assoc();        
    if($rows){
        echo $rows['mail'] . "\n";
    }else{
        echo "nothing found";
    }
}
else{
    header("Location: ./timesql_sleep.php?query=Linda");
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
