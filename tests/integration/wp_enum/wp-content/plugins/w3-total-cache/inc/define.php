<?php

/*
 * Legacy support for W3-total-cache 0.9.4 only
 */

if (@is_dir(W3TC_DIR) && file_exists(W3TC_DIR . '/w3-total-cache-api.php')) {
    require_once W3TC_DIR . '/w3-total-cache-api.php';
}

define('W3TC_LIB_W3_DIR', W3TC_DIR);

function w3_require_once($file) {
}

function w3_is_dbcluster() {
    return false;
}

class W3_Db {
    static public function instance() {
        return \W3TC\DbCache_Wpdb::instance();
    }
}

