<?php
if (isset($_GET["vuln"])) {
    echo "received '". $_GET["vuln"] . "'<br />\n";
    libxml_disable_entity_loader(false);
    $dom = new DOMDocument();
    $dom->loadXML($_GET["vuln"], LIBXML_NOENT | LIBXML_DTDLOAD); // this stuff is required to make sure
    $output = simplexml_import_dom($dom);
    echo $output;
}
?>
root:x:0: