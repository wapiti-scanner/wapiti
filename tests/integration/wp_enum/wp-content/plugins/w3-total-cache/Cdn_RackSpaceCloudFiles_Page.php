<?php
namespace W3TC;

class Cdn_RackSpaceCloudFiles_Page {
	// called from plugin-admin
	static public function admin_print_scripts_w3tc_cdn() {
		wp_enqueue_script( 'w3tc_cdn_rackspace',
			plugins_url( 'Cdn_RackSpaceCloudFiles_Page_View.js', W3TC_FILE ),
			array( 'jquery' ), '1.0' );
	}



	static public function w3tc_settings_cdn_boxarea_configuration() {
		$config = Dispatcher::config();
		$api_key = $config->get_string( 'cdn.rscf.key' );
		$authorized = !empty( $api_key );

		$cdn_host_http = '';
		$cdn_host_https = '';

		if ( $authorized ) {
			try {
				$cdn = Dispatcher::component( 'Cdn_Core' )->get_cdn();
				$cdn_host_http = $cdn->get_host_http();
				$cdn_host_https = $cdn->get_host_https();
			} catch ( \Exception $ex ) {
				$cdn_host_http = 'failed to obtain';
				$cdn_host_https = 'failed to obtain';
			}
		}

		include  W3TC_DIR . '/Cdn_RackSpaceCloudFiles_Page_View.php';
	}
}
