<?php
    if($_SERVER['REQUEST_METHOD'] === 'POST'){
        //disabling security
        libxml_use_internal_errors(true);
        libxml_disable_entity_loader(false);
        //retrieveing and parsing the xml file
        $xmlfile = file_get_contents('php://input');
        if(isset($_GET["filterword"]) && str_contains($xmlfile, $_GET['filterword']) ){
            //pursuing if all the conditions are met
            $xmlData = simplexml_load_string($xmlfile, 'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD);
            //applying filter if set
            $filterFlag = false; 
            if($xmlData !== false){
                echo $xmlData->asXML() . "\n";
            }
        }
        else echo "failed to generate XML\n";
    }else{
        echo "<!DOCTYPE html>";
        echo "<html>";
        echo "<head>";
        echo "    <title>XML Receiver</title>";
        echo "</head>";
        echo "<body>";
        echo "    <h1>XML Receiver</h1>";
        echo "    <a>This page accept XML as POST requests and will mirror it to you<a>";
        echo "</body>";
        echo "</html>";
    }
?>
