<?php
if (isset($_GET["vuln"])) {
    libxml_disable_entity_loader(false);
    $dom = new DOMDocument();
    $dom->loadXML($_GET["vuln"], LIBXML_NOENT | LIBXML_DTDLOAD); // this stuff is required to make sure
    $output = simplexml_import_dom($dom);
    echo "received";
}
?>
