<!DOCTYPE html>
<html lang="en">
<head>
    <h1>SQL vuln website</h1>
</head>
<body>
    <ul>
        <li>here is a simple webpage with 0 sanitizing <a href="./sql_easy.php?query=Linda">link 1</a></li>
        <li>here is a simple webpage with very few sanitizing <a href="./sql_medium.php?query=Linda">link 2</a></li>
        <li>here is a simple webpage with some more sanitizing <a href="./sql_hard.php?query=Linda">link 2</a></li>
    </ul>
</body>
</html>
