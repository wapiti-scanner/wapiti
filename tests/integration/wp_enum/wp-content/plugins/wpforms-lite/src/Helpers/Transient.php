<?php

namespace WPForms\Helpers;

/**
 * WPForms Transients implementation.
 *
 * @since 1.6.3.1
 */
class Transient {

	/**
	 * Transient option name prefix.
	 *
	 * @since 1.6.3.1
	 *
	 * @var string
	 */
	const OPTION_PREFIX = '_wpforms_transient_';

	/**
	 * Transient timeout option name prefix.
	 *
	 * @since 1.6.3.1
	 *
	 * @var string
	 */
	const TIMEOUT_PREFIX = '_wpforms_transient_timeout_';

	/**
	 * Get the value of a transient.
	 *
	 * If the transient does not exist, does not have a value, or has expired,
	 * then the return value will be false.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient Transient name. Expected to not be SQL-escaped.
	 *
	 * @return mixed Value of transient.
	 */
	public static function get( $transient ) {

		$transient_option  = self::OPTION_PREFIX . $transient;
		$transient_timeout = self::TIMEOUT_PREFIX . $transient;

		$alloptions = wp_load_alloptions();

		// If option is not in alloptions, it is not autoloaded and thus has a timeout to check.
		if ( ! isset( $alloptions[ $transient_option ] ) ) {
			$is_expired = self::is_expired( $transient );
		}

		// Return the data if it's not expired.
		if ( empty( $is_expired ) ) {
			return self::get_option( $transient );
		}

		delete_option( $transient_option );
		delete_option( $transient_timeout );

		return false;
	}

	/**
	 * Set/update the value of a transient.
	 *
	 * You do not need to serialize values. If the value needs to be serialized, then
	 * it will be serialized before it is set.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient  Transient name. Expected to not be SQL-escaped. Must be
	 *                           164 characters or fewer.
	 * @param mixed  $value      Transient value. Must be serializable if non-scalar.
	 *                           Expected to not be SQL-escaped.
	 * @param int    $expiration Optional. Time until expiration in seconds. Default 0 (no expiration).
	 *
	 * @return bool False if value was not set and true if value was set.
	 */
	public static function set( $transient, $value, $expiration = 0 ) {

		if ( false === self::get_option( $transient ) ) {
			return self::add( $transient, $value, $expiration );
		}

		return self::update( $transient, $value, $expiration );
	}

	/**
	 * Create a new transient with a given value.
	 *
	 * Internal method, use Transient::set() instead.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient  Transient name. Expected to not be SQL-escaped. Must be
	 *                           164 characters or fewer.
	 * @param mixed  $value      Transient value. Must be serializable if non-scalar.
	 *                           Expected to not be SQL-escaped.
	 * @param int    $expiration Optional. Time until expiration in seconds. Default 0 (no expiration).
	 *
	 * @return bool False if value was not set and true if value was set.
	 */
	private static function add( $transient, $value, $expiration ) {

		if ( $expiration ) {
			add_option( self::TIMEOUT_PREFIX . $transient, time() + $expiration, '', 'no' );
		}

		// If there's an expiration, the option won't be autoloaded.
		return add_option( self::OPTION_PREFIX . $transient, $value, '', $expiration ? 'no' : 'yes' );
	}

	/**
	 * Update the value of a transient.
	 *
	 * Internal method, use Transient::set() instead.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient  Transient name. Expected to not be SQL-escaped. Must be
	 *                           164 characters or fewer.
	 * @param mixed  $value      Transient value. Must be serializable if non-scalar.
	 *                           Expected to not be SQL-escaped.
	 * @param int    $expiration Optional. Time until expiration in seconds. Default 0 (no expiration).
	 *
	 * @return bool False if value was not set and true if value was set.
	 */
	private static function update( $transient, $value, $expiration ) {

		$transient_option  = self::OPTION_PREFIX . $transient;
		$transient_timeout = self::TIMEOUT_PREFIX . $transient;

		if ( ! $expiration ) {
			return update_option( $transient_option, $value );
		}

		$timeout = self::get_timeout( $transient );

		if ( false !== $timeout ) {
			update_option( $transient_timeout, time() + $expiration );
			return update_option( $transient_option, $value );
		}

		// If expiration is requested, but the transient has no timeout option,
		// delete, then re-create transient rather than update.
		delete_option( $transient_option );
		add_option( $transient_timeout, time() + $expiration, '', 'no' );

		return add_option( $transient_option, $value, '', 'no' );
	}

	/**
	 * Delete a transient.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient Transient name. Expected to not be SQL-escaped.
	 *
	 * @return bool true if successful, false otherwise
	 */
	public static function delete( $transient ) {

		$result = delete_option( self::OPTION_PREFIX . $transient );

		if ( $result ) {
			delete_option( self::TIMEOUT_PREFIX . $transient );
		}

		return $result;
	}

	/**
	 * Delete all WPForms transients.
	 *
	 * @since 1.6.3.1
	 *
	 * @return int|false Number of rows affected/selected or false on error
	 */
	public static function delete_all() {

		global $wpdb;

		return $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options}
				WHERE option_name LIKE %s",
				$wpdb->esc_like( self::OPTION_PREFIX ) . '%'
			)
		);
	}

	/**
	 * Delete all expired WPForms transients.
	 *
	 * The multi-table delete syntax is used to delete the transient record
	 * from table a, and the corresponding transient_timeout record from table b.
	 *
	 * @since 1.6.3.1
	 *
	 * @return int|false Number of rows affected/selected or false on error
	 */
	public static function delete_all_expired() {

		global $wpdb;

		return $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b
				WHERE a.option_name LIKE %s
				AND a.option_name NOT LIKE %s
				AND b.option_name = CONCAT( %s, SUBSTRING( a.option_name, %d ) )
				AND b.option_value < %d",
				$wpdb->esc_like( self::OPTION_PREFIX ) . '%',
				$wpdb->esc_like( self::TIMEOUT_PREFIX ) . '%',
				self::TIMEOUT_PREFIX,
				strlen( self::OPTION_PREFIX ) + 1,
				time()
			)
		);
	}

	/**
	 * Check if transient is expired.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient Transient name. Expected to not be SQL-escaped.
	 *
	 * @return bool true if expired, false otherwise
	 */
	public static function is_expired( $transient ) {

		$timeout = self::get_timeout( $transient );

		// If there's no timeout data found, the transient is considered to be valid.
		if ( false === $timeout ) {
			return false;
		}

		if ( $timeout >= time() ) {
			return false;
		}

		return true;
	}

	/**
	 * Get a transient option value.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient Transient name. Expected to not be SQL-escaped.
	 *
	 * @return mixed Value set for the option.
	 */
	private static function get_option( $transient ) {

		return get_option( self::OPTION_PREFIX . $transient );
	}

	/**
	 * Get a transient timeout option value.
	 *
	 * @since 1.6.3.1
	 *
	 * @param string $transient Transient name. Expected to not be SQL-escaped.
	 *
	 * @return mixed Value set for the option.
	 */
	private static function get_timeout( $transient ) {

		return get_option( self::TIMEOUT_PREFIX . $transient );
	}
}
