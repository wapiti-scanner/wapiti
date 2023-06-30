<?php
function partialSanitize($str){
	$lowStr=strtolower($str);
	if(strpos($lowStr, "alert") || strpos($lowStr, "script") || strpos($lowStr, "svg")) return "blocked";
	else return $str;
}
function jsfuckSanitize($str){
	// This will only let JSFuck pass
	$pattern="/<script>[\(\)\(\)\[\]\+!]+<\/script>/i";
	if(preg_match($pattern, $str)) return $str;
	else return preg_replace("/[<>\/]/i", '', $str);
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message']) && isset($_GET['level'])) {
  echo 'yes';
  switch ($_GET['level']){
    case '1':
      # This is the easy case, full passthrough
      $message = $_POST['message'];
      break;
    case '2':
      # Partial sanitize
      $message = partialSanitize($_POST['message']);
      break;
    case '3':
      # Only let jsfuck pass
      $message = jsfuckSanitize($_POST['message']);
      break;
    default:
      $message = "can't process";
      break;
  }
  // Store the user's input (vulnerable to XSS)
  file_put_contents('messages.txt', $message . "\n", FILE_APPEND);
}
elseif(!isset($_GET['level'])){
  header_remove();
  header('Location: ' . $_SERVER['PHP_SELF'] . '?level=1');
}
?>
<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Website</title>
</head>
<body>
  <h1>Welcome to the Vulnerable Website!</h1>
  <form action=<?php echo "form.php?level=" . $_GET['level'];?> method="POST">
    <label for="message">Enter a message:</label>
    <input type="text" name="message" id="message" />
    <input type="submit" value="Submit" />
  </form>
  <h2>Stored Messages:</h2>
<div>
  <?php
  $filename = 'messages.txt';

  if (file_exists($filename)) {
    $messages = file($filename, FILE_IGNORE_NEW_LINES);
    foreach ($messages as $message) {
      echo "<p>{$message}</p>";
    }
  } else {
    echo "<p>No messages found.</p>";
  }
  ?>
</div>
</body>
</html>
