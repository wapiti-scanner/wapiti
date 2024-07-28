<!DOCTYPE html>
<html>
<head>
    <title>Users Directory</title>
</head>
<body>
<h2>Users Directory</h2>
<form method="post">
    <label for="searchTerm">Search users by firstname or lastname:</label>
    <input size="30" type="text" id="searchTerm" name="searchTerm" required>
    <br />
    <input type="submit" value="Search">
</form>
<?php

include("config.php");

function searchUsers($searchTerm, $text) {
    $ldapConn = ldap_connect(LDAP_HOST, LDAP_PORT);
    if (!$ldapConn) {
        exit('ldap_conn');
    }

    ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
    $ldapBind = @ldap_bind($ldapConn, LDAP_DN, LDAP_PASS);

    $filter = "(&(cn=*$searchTerm*))";
    echo "<!-- $filter -->\n";
    $ldapSearch = ldap_search($ldapConn, "ou=users,dc=example,dc=org", $filter);
    if ($ldapSearch) {
        $entries = ldap_get_entries($ldapConn, $ldapSearch);
        if ($entries['count'] > 0) {
            $text .= "<h3>Users matching your query:</h3>";
            $text .= "<ul>";
            for ($i = 0; $i < $entries['count']; $i++) {
                $uid = $entries[$i]['uid'][0];
                $cn = $entries[$i]['cn'][0];
                $email = $entries[$i]['mail'][0];
                $text .= "<li><strong>UID:</strong> $uid, <strong>CN:</strong> $cn, <strong>Mail:</strong> $email</li>";
            }
            $text .= "</ul>";
        } else {
            $text .= "<p>No user matched your terms: $searchTerm</p>";
        }
    } else {
        $text .= "<p>An error occured during the search</p>";
    }
    ldap_close($ldapConn);
    return $text;
}

$text = "";
if (isset($_REQUEST['searchTerm'])) {
    $searchTerm = $_REQUEST['searchTerm'];
    if (!empty($searchTerm)) {
        $text = searchUsers($searchTerm, $text);
    } else {
        $text = "<p>Please specify a search term</p>";
    }
}
?>
<?php echo $text; ?>
</body>
</html>
