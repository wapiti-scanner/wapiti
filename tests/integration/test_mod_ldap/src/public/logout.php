<?php
    session_start();
    session_destroy();
    header('Location: /', true , 301);
?>
