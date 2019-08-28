<?php
if (isset($_GET["vuln1"])) {
  if (substr($_GET["vuln1"], 0, 5) === "sleep") {
    sleep(2);
  }
}

if (isset($_GET["vuln2"])) {
  // false positive
  sleep(2);
}
?>