<?php

session_start();

include("config.php");

if (isset($_POST["logout"])) {
    session_destroy();
    header('Location: /', true , 301);
    exit;
}

if (isset($_REQUEST["login"])) {
    $userId = $_REQUEST["user_id"];
    $password = $_REQUEST['password'];

    $ldapConn = ldap_connect(LDAP_HOST, LDAP_PORT);
    if (!$ldapConn) {
        exit('ldap_conn');
    }

    ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
    $ldapBind = @ldap_bind($ldapConn, LDAP_DN, LDAP_PASS);
    if ($ldapBind) {
        $filter = '(&(uid=' . $userId . ')(title=' . $password . '))';
        $ldapSearch = ldap_search($ldapConn, LDAP_DC, $filter);
        $getEntries = ldap_get_entries($ldapConn, $ldapSearch);

        if ($getEntries['count'] > 0) {
            // Successful authentication
            $_SESSION["USERID"] = $userId;
        } else {
            echo "Bad credentials\n<br />";
        }
    } else {
        echo "Could not contact the backend server\n<br />";
    }
}

?>

<html>
<?php if (isset($_SESSION["USERID"])) {
  echo "Welcome ".$_SESSION["USERID"]."\n<br />";
?>
<a href="logout.php">Logout</a><br />
<?php
} else {
?>
<form method="POST">
    <label>User ID: </label><input type="text" name="user_id"/>
    <label>Password: </label><input type="password" name="password"/>
    <input type="hidden" name="login" value="1"/>
    <input type="submit" name="submit" value="Submit"/>
</form>
<?php
}
?>

<br />
<a href="search.php">Search our directory</a>
</html>
