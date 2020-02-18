<html>
    <head>
        <title><?php
$title = isset($_GET["title"]) ? $_GET["title"] : "Untitled";
if (isset($_GET["fixed"])) {
    echo str_ireplace("</title", "sucker", $title);
} else {
    echo $title;
}
?></title>
    </head>
    <body>
        This is dope!
    </body>
</html>

