<?php
/**
 * Health class.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * Health class.
 */
class Health {

	/**
	 * Prefix of the blog lock transient.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const STATUS_OPTION = 'sync_health_status';

	/**
	 * Status key in option array.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const OPTION_STATUS_KEY = 'status';

	/**
	 * Timestamp key in option array.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const OPTION_TIMESTAMP_KEY = 'timestamp';

	/**
	 * Unknown status code.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const STATUS_UNKNOWN = 'unknown';

	/**
	 * Disabled status code.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const STATUS_DISABLED = 'disabled';

	/**
	 * Out of sync status code.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const STATUS_OUT_OF_SYNC = 'out_of_sync';

	/**
	 * In sync status code.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const STATUS_IN_SYNC = 'in_sync';

	/**
	 * If sync is active, Health-related hooks will be initialized after plugins are loaded.
	 */
	public static function init() {
		add_action( 'jetpack_full_sync_end', array( __CLASS__, 'full_sync_end_update_status' ), 10, 2 );
	}

	/**
	 * Gets health status code.
	 *
	 * @return string Sync Health Status
	 */
	public static function get_status() {
		$status = \Jetpack_Options::get_option( self::STATUS_OPTION );

		if ( false === $status || ! is_array( $status ) || empty( $status[ self::OPTION_STATUS_KEY ] ) ) {
			return self::STATUS_UNKNOWN;
		}

		switch ( $status[ self::OPTION_STATUS_KEY ] ) {
			case self::STATUS_DISABLED:
			case self::STATUS_OUT_OF_SYNC:
			case self::STATUS_IN_SYNC:
				return $status[ self::OPTION_STATUS_KEY ];
			default:
				return self::STATUS_UNKNOWN;
		}
	}

	/**
	 * When the Jetpack plugin is upgraded, set status to disabled if sync is not enabled,
	 * or to unknown, if the status has never been set before.
	 */
	public static function on_jetpack_upgraded() {
		if ( ! Settings::is_sync_enabled() ) {
			self::update_status( self::STATUS_DISABLED );
			return;
		}
		if ( false === self::is_status_defined() ) {
			self::update_status( self::STATUS_UNKNOWN );
		}
	}

	/**
	 * When the Jetpack plugin is activated, set status to disabled if sync is not enabled,
	 * or to unknown.
	 */
	public static function on_jetpack_activated() {
		if ( ! Settings::is_sync_enabled() ) {
			self::update_status( self::STATUS_DISABLED );
			return;
		}
		self::update_status( self::STATUS_UNKNOWN );
	}

	/**
	 * Updates sync health status with either a valid status, or an unknown status.
	 *
	 * @param string $status Sync Status.
	 *
	 * @return bool True if an update occoured, or false if the status didn't change.
	 */
	public static function update_status( $status ) {
		if ( self::get_status() === $status ) {
			return false;
		}
		// Default Status Option.
		$new_status = array(
			self::OPTION_STATUS_KEY    => self::STATUS_UNKNOWN,
			self::OPTION_TIMESTAMP_KEY => microtime( true ),
		);

		switch ( $status ) {
			case self::STATUS_DISABLED:
			case self::STATUS_OUT_OF_SYNC:
			case self::STATUS_IN_SYNC:
				$new_status[ self::OPTION_STATUS_KEY ] = $status;
				break;
		}

		\Jetpack_Options::update_option( self::STATUS_OPTION, $new_status );
		return true;
	}

	/**
	 * Check if Status has been previously set.
	 *
	 * @return bool is a Status defined
	 */
	public static function is_status_defined() {
		$status = \Jetpack_Options::get_option( self::STATUS_OPTION );

		if ( false === $status || ! is_array( $status ) || empty( $status[ self::OPTION_STATUS_KEY ] ) ) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Update Sync Status if Full Sync ended of Posts
	 *
	 * @param string $checksum The checksum that's currently being processed.
	 * @param array  $range The ranges of object types being processed.
	 */
	public static function full_sync_end_update_status( $checksum, $range ) {
		if ( isset( $range['posts'] ) ) {
			self::update_status( self::STATUS_IN_SYNC );
		}
	}

}
