<?php

if(isset($_GET['user-agent'])) {
  $user_agent = $_GET['user-agent'];
  // header() in php now prevent CRLF so here is a workaround
  $headers_arr = preg_split('/\r\n|\r|\n/', $user_agent);
  header_remove();
  header("User-Agent: $headers_arr[0]");
  if(count($headers_arr)>1){
    for($i=1;$i<count($headers_arr); $i++){
        header($headers_arr[$i]);
    }
  }
}
else{
  // Set the value of the "param" parameter to "blabla"
  $param_value = "blabla";
  $url = "index.php?user-agent=" . $param_value;

  // Redirect to the URL with the parameter
  header("Location: " . $url);
}
?>

<!DOCTYPE html>
<html>
<head>
	<title>CRLF Example</title>
</head>
    <body>
        <p>Page where you can do some injections into the user_agent param and header.</p>
    </body>
</html>

