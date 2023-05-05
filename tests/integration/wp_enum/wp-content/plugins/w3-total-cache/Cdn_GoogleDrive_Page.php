<?php
/**
 * File: Cdn_GoogleDrive_Page.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Cdn_GoogleDrive_Page
 */
class Cdn_GoogleDrive_Page {
	/**
	 * Print scripts.
	 *
	 * Called from plugin-admin.
	 */
	public static function admin_print_scripts_w3tc_cdn() {
		wp_enqueue_script(
			'w3tc_cdn_google_drive',
			plugins_url( 'Cdn_GoogleDrive_Page_View.js', W3TC_FILE ),
			array( 'jquery' ),
			'1.0',
			false
		);

		$path       = 'admin.php?page=w3tc_cdn';
		$return_url = self_admin_url( $path );

		wp_localize_script(
			'w3tc_cdn_google_drive',
			'w3tc_cdn_google_drive_url',
			array( W3TC_GOOGLE_DRIVE_AUTHORIZE_URL . '?return_url=' . rawurlencode( $return_url ) )
		);

		// it's return from google oauth.
		if ( ! empty( Util_Request::get_string( 'oa_client_id' ) ) ) {
			$path = wp_nonce_url( 'admin.php', 'w3tc' ) .
				'&page=w3tc_cdn&w3tc_cdn_google_drive_auth_return';
			foreach ( $_GET as $key => $value ) { // phpcs:ignore
				if ( substr( $key, 0, 3 ) === 'oa_' ) {
					$path .= '&' . rawurlencode( $key ) . '=' . rawurlencode( Util_Request::get_string( $key ) );
				}
			}

			$popup_url = self_admin_url( $path );

			wp_localize_script(
				'w3tc_cdn_google_drive',
				'w3tc_cdn_google_drive_popup_url',
				array( $popup_url )
			);

		}
	}

	/**
	 * Load view.
	 */
	public static function w3tc_settings_cdn_boxarea_configuration() {
		$config = Dispatcher::config();
		require W3TC_DIR . '/Cdn_GoogleDrive_Page_View.php';
	}
}
