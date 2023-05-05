<?php
/**
 * Jetpack Connection Status.
 *
 * Filters the Connection Status API response
 *
 * @package jetpack
 */

/**
 * Filters the Connection Status API response
 */
class Jetpack_Connection_Status {

	/**
	 * Initialize the main hooks.
	 */
	public static function init() {
		add_filter( 'jetpack_connection_status', array( __CLASS__, 'filter_connection_status' ) );
	}

	/**
	 * Filters the connection status API response of the Connection package and modifies isActive value expected by the UI.
	 *
	 * @param array $status An array containing the connection status data.
	 */
	public static function filter_connection_status( $status ) {

		$status['isActive'] = Jetpack::is_connection_ready();

		return $status;
	}

}
