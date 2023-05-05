<?php
namespace W3TC;



class Extension_Genesis_Page {
	static public function w3tc_extension_page_genesis_theme() {
		$config = Dispatcher::config();
		include  W3TC_DIR . '/Extension_Genesis_Page_View.php';
	}
}
