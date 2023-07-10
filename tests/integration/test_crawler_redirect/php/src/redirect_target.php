<!DOCTYPE html>
<html>

<head>
    <title>Target</title>
</head>

<body>
    <p>Target reached</p>
    <?php
    if(isset($_GET['origin'])){
        echo '<p>Origin page was'. $_GET['origin'] .'</p>';
    }
    else{
        echo '<p>Origin page not supplied</p>';
    }
    ?>
</body>

</html>
