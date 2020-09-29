<html>
<body>
<?php
if (isset($_POST["email"])) {
    if (isset($_GET["check"])) {
        if ($_POST["xsrf_token"] == "weak") echo "Password reset for ".$_POST["email"];
        else echo "CSRF error";
    } else {
        echo "Password reset for ".$_POST["email"];
    }
} else {
?>
Password reset<br />
<form method="POST">
email: <input type=text name=email />
<input type="hidden" name="xsrf_token" value="weak" />
<input type="submit" value="submit" />
</form>
<?php
}
?>
</body>
</html>
