<?php
// http://colesec.inventedtheinternet.com/attacking-xml-with-xml-external-entity-injection-xxe/
libxml_disable_entity_loader(false);
if (isset($_SERVER["CONTENT_TYPE"])) {
    if ($_SERVER["CONTENT_TYPE"] == "text/xml") {
        $xmlfile = file_get_contents('php://input');
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); // this stuff is required to make sure
        $output = simplexml_import_dom($dom);
        echo $output;
    }
}
?>
