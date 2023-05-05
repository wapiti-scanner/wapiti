<?php
namespace W3TC;

class Extension_Wpml_Plugin {
	private $_config;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	public function run() {
		if ( Util_Environment::is_w3tc_pro( $this->_config ) ) {
			add_filter( 'w3tc_url_to_docroot_filename',
				array( $this, 'w3tc_url_to_docroot_filename' ) );
		}
	}



	public function w3tc_url_to_docroot_filename( $data ) {
		$home_url = $data['home_url'];

		if ( substr( $data['url'], 0, strlen( $home_url ) ) != $home_url ) {
			$data['home_url'] = get_option( 'home' );
		}

		return $data;
	}
}



$p = new Extension_Wpml_Plugin();
$p->run();

if ( is_admin() ) {
	$p = new Extension_Wpml_Plugin_Admin();
	$p->run();
}
