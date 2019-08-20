XXE playground<br />

<a href="param.php?yolo=nawak&vuln=here">Vulnerable parameter</a><br />

<form method="POST" action="body.php">
<input type="text" name="placeholder" />
<input type="submit" value="Send to vulnerable form" />
</form>
<br />

<a href="upload.php">Vulnerable upload form</a><br />

<a href="qs.php">Vulnerable query string</a>
