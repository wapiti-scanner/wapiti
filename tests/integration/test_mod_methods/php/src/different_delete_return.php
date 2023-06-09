<!DOCTYPE html>
<html>
<head>
    <title>Different Delete</title>
</head>
<body>
    <p>This page has a different return response for the DELETE method</p>
    <?php
    if($_SERVER['REQUEST_METHOD'] === 'DELETE'){
        echo "<p>A different body</p>\n";
    }else{
        echo "<p>A normal body</p>\n";
    }
    ?>
</body>
</html>
