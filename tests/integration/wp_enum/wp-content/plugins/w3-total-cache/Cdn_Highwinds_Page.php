<?php
namespace W3TC;

class Cdn_Highwinds_Page {
	// called from plugin-admin
	static public function admin_print_scripts_w3tc_cdn() {
		wp_enqueue_script( 'w3tc_cdn_highwinds',
			plugins_url( 'Cdn_Highwinds_Page_View.js', W3TC_FILE ),
			array( 'jquery' ), '1.0' );
	}



	static public function w3tc_settings_cdn_boxarea_configuration() {
		$config = Dispatcher::config();
		include  W3TC_DIR . '/Cdn_Highwinds_Page_View.php';
	}
}
