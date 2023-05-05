<?php
/**
 * The React initial state.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Status;

/**
 * The React initial state.
 */
class Initial_State {

	/**
	 * Whether the initial state was already rendered
	 *
	 * @var boolean
	 */
	private static $rendered = false;

	/**
	 * Get the initial state data.
	 *
	 * @return array
	 */
	private static function get_data() {
		global $wp_version;

		return array(
			'apiRoot'            => esc_url_raw( rest_url() ),
			'apiNonce'           => wp_create_nonce( 'wp_rest' ),
			'registrationNonce'  => wp_create_nonce( 'jetpack-registration-nonce' ),
			'connectionStatus'   => REST_Connector::connection_status( false ),
			'userConnectionData' => REST_Connector::get_user_connection_data( false ),
			'connectedPlugins'   => REST_Connector::get_connection_plugins( false ),
			'wpVersion'          => $wp_version,
			'siteSuffix'         => ( new Status() )->get_site_suffix(),
			'connectionErrors'   => Error_Handler::get_instance()->get_verified_errors(),
		);
	}

	/**
	 * Render the initial state into a JavaScript variable.
	 *
	 * @return string
	 */
	public static function render() {
		if ( self::$rendered ) {
			return null;
		}
		self::$rendered = true;
		return 'var JP_CONNECTION_INITIAL_STATE=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( self::get_data() ) ) . '"));';
	}

}
