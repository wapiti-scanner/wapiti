<?php
/**
 * File: Cdnfsd_TransparentCDN_Page.php
 *
 * @since 0.15.0
 */

namespace W3TC;

/**
 * Class: Cdnfsd_TransparentCDN_Page
 *
 * @since 0.15.0
 */
class Cdnfsd_TransparentCDN_Page {
	/**
	 * Test API parameters.
	 *
	 * Called from plugin-admin.
	 *
	 * @since 0.15.0
	 * @static
	 */
	static public function admin_test_api_parameters_transparentcdn() {
		wp_register_script(
			'w3tc_cdn_transparentcdn_fsd',
			plugins_url( 'Cdnfsd_TransparentCDN_Page_View.js', W3TC_FILE )
		);

		wp_localize_script(
			'w3tc_cdn_transparentcdn_fsd', 'transparent_configuration_strings',
			array(
				'test_string'  => __( 'Test the API parameters offered for you site', 'w3-total-cache') ,
				'test_success' => __( 'Ok. Correct parameters', 'w3-total-cache', 'w3-total-cache' ),
				'test_failure' => __( 'Error. Check your parameters and try again or contact with support.', 'w3-total-cache' ),
			)
		);

		wp_enqueue_script(
			'w3tc_cdn_transparentcdn_fsd',
			plugins_url( 'Cdnfsd_TransparentCDN_Page_View.js', W3TC_FILE ),
			array( 'jquery' ),
			'1.0',
			true
		);
	}

	/**
	 * Render the settings box.
	 *
	 * @since 0.15.0
	 */
	static public function w3tc_settings_box_cdnfsd() {
		$config = Dispatcher::config();
		require W3TC_DIR . '/Cdnfsd_TransparentCDN_Page_View.php';
	}
}
