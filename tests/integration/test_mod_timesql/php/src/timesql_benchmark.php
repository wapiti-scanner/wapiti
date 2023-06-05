<?php
if(isset($_GET['query']) && !preg_match("/.*sleep.*/i", $_GET['query'])){
    //let requests not containing the word "sleep" pass
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
    // echo "query#2: " . $query
    if(preg_match("/.*benchmark.*/", $_GET['query'])){
        // adding some 0 to make some latency and using another request to make 
        // it works
        $query = preg_replace('/0000000/', '$0' . str_repeat('0', 8),$_GET['query']);
        echo "query: " . $query;
        $row = $conn->query("SELECT mail FROM users WHERE name='" . $query . ';')->fetch_assoc();
    }else{
        $rows =  $conn->query('SELECT mail FROM users WHERE name="' . $_GET['query'] . '";')->fetch_assoc();
    }        
    if($rows){
        echo $rows['mail'] . "\n";
    }else{
        echo "nothing found";
    }
}
else{
    header("Location: ./timesql_benchmark.php?query=Linda");
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
