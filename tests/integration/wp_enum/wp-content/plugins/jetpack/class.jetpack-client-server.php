<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Client = Plugin
 * Client Server = API Methods the Plugin must respond to
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Webhooks;

/**
 * Client = Plugin
 * Client Server = API Methods the Plugin must respond to
 */
class Jetpack_Client_Server {

	/**
	 * Handle the client authorization error.
	 *
	 * @param WP_Error $error The error object.
	 */
	public static function client_authorize_error( $error ) {
		if ( $error instanceof WP_Error ) {
			Jetpack::state( 'error', $error->get_error_code() );
		}
	}

	/**
	 * The user is already authorized, we set the Jetpack state and adjust the redirect URL.
	 *
	 * @return string
	 */
	public static function client_authorize_already_authorized_url() {
		Jetpack::state( 'message', 'already_authorized' );
		return Jetpack::admin_url();
	}

	/**
	 * The authorization processing has started.
	 */
	public static function client_authorize_processing() {
		Jetpack::log( 'authorize' );
	}

	/**
	 * The authorization has completed (successfully or not), and the redirect URL is empty.
	 * We set the Jetpack Dashboard as the default URL.
	 *
	 * @return string
	 */
	public static function client_authorize_fallback_url() {
		return Jetpack::admin_url();
	}

	/**
	 * Authorization handler.
	 *
	 * @deprecated since Jetpack 9.5.0
	 * @see Webhooks::handle_authorize()
	 */
	public function client_authorize() {
		_deprecated_function( __METHOD__, 'jetpack-9.5.0', 'Automattic\\Jetpack\\Connection\\Webhooks::handle_authorize' );
		( new Webhooks() )->handle_authorize();
	}

	/**
	 * Deactivate a plugin.
	 *
	 * @param string $probable_file Expected plugin file.
	 * @param string $probable_title Expected plugin title.
	 * @return int 1 if a plugin was deactivated, 0 if not.
	 */
	public static function deactivate_plugin( $probable_file, $probable_title ) {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		if ( is_plugin_active( $probable_file ) ) {
			deactivate_plugins( $probable_file );
			return 1;
		} else {
			// If the plugin is not in the usual place, try looking through all active plugins.
			$active_plugins = Jetpack::get_active_plugins();
			foreach ( $active_plugins as $plugin ) {
				$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
				if ( $data['Name'] === $probable_title ) {
					deactivate_plugins( $plugin );
					return 1;
				}
			}
		}

		return 0;
	}

	/**
	 * Get the Jetpack instance.
	 *
	 * @deprecated since Jetpack 9.5.0
	 * @see Jetpack::init()
	 */
	public function get_jetpack() {
		_deprecated_function( __METHOD__, 'jetpack-9.5.0', 'Jetpack::init' );
		return Jetpack::init();
	}

	/**
	 * No longer used.
	 *
	 * @deprecated since Jetpack 9.5.0
	 */
	public function do_exit() {
		_deprecated_function( __METHOD__, 'jetpack-9.5.0' );
		exit;
	}
}
