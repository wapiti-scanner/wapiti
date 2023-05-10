<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>CMD Injections</title>
    </head>

    <body>
        <p>Here you can use the cmd attribute to inject commands</p>
        <ul>
            <li>inject commands directly <a href="./direct_exec.php/?cmd=echo">on this page</a></li>
            <li>inject commands as curl parameters <a href="./argument_inject.php/?args=/var/log">on this page</a></li>
            <li>inject commands with some string processing <a href="./last_payload.php/?abc=blabla">on this page</a></li>
        </ul>
    </body>
</html>
