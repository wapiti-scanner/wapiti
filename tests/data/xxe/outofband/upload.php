<?php
if (isset($_FILES["calendar"])) {
    libxml_disable_entity_loader(false);
    $dom = new DOMDocument();
    move_uploaded_file($_FILES["calendar"]["tmp_name"], "/dev/shm/wapiti.xml");
    $calendar = file_get_contents("/dev/shm/wapiti.xml");
    $dom->loadXML($calendar, LIBXML_NOENT | LIBXML_DTDLOAD);
    $output = simplexml_import_dom($dom);
    echo "Data loaded.";
} else {
?>
    <form method="POST" enctype="multipart/form-data">
        Please send your xml calendar: <input type="file" name="calendar"/ >
        <input type="submit" value="Submit" />
    </form>
<?php
}
?>
