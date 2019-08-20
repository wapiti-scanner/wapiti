<?php
if (isset($_SERVER["QUERY_STRING"])) {
    libxml_disable_entity_loader(false);
    $dom = new DOMDocument();
    echo "'".$_SERVER["QUERY_STRING"]."'<br />\n";
    $dom->loadXML(urldecode($_SERVER["QUERY_STRING"]), LIBXML_NOENT | LIBXML_DTDLOAD); // this stuff is required to make sure
    $output = simplexml_import_dom($dom);
    echo $output;
}
?>
