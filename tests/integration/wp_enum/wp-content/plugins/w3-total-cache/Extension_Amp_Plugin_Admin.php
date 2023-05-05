<?php
namespace W3TC;

class Extension_Amp_Plugin_Admin {
	static public function w3tc_extensions( $extensions, $config ) {
		$enabled = true;
		$disabled_message = '';

		$requirements = array();

		$extensions['amp'] = array(
			'name' => 'AMP',
			'author' => 'W3 EDGE',
			'description' => __( 'Adds compatibility for accelerated mobile pages (AMP) to minify.',
				'w3-total-cache' ),
			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'amp',
			'settings_exists' => true,
			'version' => '0.1',
			'enabled' => $enabled,
			'disabled_message' => $disabled_message,
			'requirements' => implode( ', ', $requirements ),
			'path' => 'w3-total-cache/Extension_Amp_Plugin.php'
		);

		return $extensions;
	}



	static public function w3tc_extension_load_admin() {
		$o = new Extension_Amp_Plugin_Admin();

		add_action( 'w3tc_extension_page_amp',
			array( $o, 'w3tc_extension_page_amp' ) );
		add_action( 'w3tc_config_save',
			array( $o, 'w3tc_config_save' ), 10, 1 );
	}



	public function w3tc_extension_page_amp() {
		include W3TC_DIR . '/Extension_Amp_Page_View.php';
	}



	public function w3tc_config_save( $config ) {
		// frontend activity
		$url_type = $config->get_string( array( 'amp', 'url_type' ) );
		$is_active_dropin = ($url_type == 'querystring');

		$config->set_extension_active_dropin( 'amp', $is_active_dropin );
	}
}
