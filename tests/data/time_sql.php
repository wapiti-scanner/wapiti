<?php
if (isset($_GET["vuln1"])) {
  if (substr($_GET["vuln1"], 0, 5) === "sleep") {
    sleep(3);
  }
}

if (isset($_GET["vuln2"])) {
  if (substr($_GET["vuln2"], 0, 5) === "sleep") {
    sleep(3);
  }
}
?>