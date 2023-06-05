<!DOCTYPE html>
<html lang="en">
<head>
    <h1>SQL vuln website</h1>
</head>
<body>
    <ul>
        <li>here is a simple webpage with 0 sanitizing <a href="/timesql_sleep.php?query=Linda">link 1</a></li>
        <li>here is a simple webpage with very few sanitizing <a href="./timesql_benchmark.php?query=Linda">link 2</a></li>
    </ul>
</body>
</html>
