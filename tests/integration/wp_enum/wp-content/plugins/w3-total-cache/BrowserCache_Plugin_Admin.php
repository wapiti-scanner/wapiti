<?php
namespace W3TC;

class BrowserCache_Plugin_Admin {
	function run() {
		$config_labels = new BrowserCache_ConfigLabels();
		add_filter( 'w3tc_config_labels', array(
				$config_labels, 'config_labels' ) );

		add_action( 'w3tc_ajax',
			array( '\W3TC\BrowserCache_Page', 'w3tc_ajax' ) );

		add_action( 'w3tc_config_ui_save-w3tc_browsercache',
			array( $this, 'w3tc_config_ui_save_w3tc_browsercache' ),
			10, 2 );
	}



	public function w3tc_config_ui_save_w3tc_browsercache( $config, $old_config ) {
		$prefix = 'browsercache__security__fp__values__keyvalues__';
		$prefixl = strlen( $prefix );

		$fp_values = array();

		foreach ( $_REQUEST as $key => $value ) {
			$value = Util_Request::get_string( $key );
			if ( substr( $key, 0, $prefixl ) == $prefix ) {
				$k = substr( $key, $prefixl );
				if ( !empty( $value ) ) {
					$fp_values[$k] = $value;
				}
			}
		}

		$config->set( 'browsercache.security.fp.values', $fp_values );
	}
}
