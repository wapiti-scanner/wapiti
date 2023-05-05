<?php
namespace W3TC;

class Cdn_RackSpaceCdn_Page {
	// called from plugin-admin
	static public function w3tc_admin_actions( $handlers ) {
		$handlers['cdn_rackspace_cdn'] = 'Cdn_RackSpaceCdn_AdminActions';

		return $handlers;
	}

	// called from plugin-admin
	static public function admin_print_scripts_w3tc_cdn() {
		wp_enqueue_script( 'w3tc_cdn_rackspace',
			plugins_url( 'Cdn_RackSpaceCdn_Page_View.js', W3TC_FILE ),
			array( 'jquery' ), '1.0' );
	}



	static public function w3tc_settings_cdn_boxarea_configuration() {
		$config = Dispatcher::config();
		$api_key = $config->get_string( 'cdn.rackspace_cdn.api_key' );
		$authorized = !empty( $api_key );

		$access_url_full = '';
		if ( $authorized ) {
			$p = $config->get_string( 'cdn.rackspace_cdn.service.protocol' );
			$access_url_full =
				( $p == 'https' ? 'https://' : 'http://' ) .
				$config->get_string( 'cdn.rackspace_cdn.service.access_url' );
		}

		include  W3TC_DIR . '/Cdn_RackSpaceCdn_Page_View.php';
	}
}
