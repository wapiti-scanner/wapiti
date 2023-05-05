<?php
/**
 * The nonce handler.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

/**
 * The nonce handler.
 */
class Nonce_Handler {

	/**
	 * How long the scheduled cleanup can run (in seconds).
	 * Can be modified using the filter `jetpack_connection_nonce_scheduled_cleanup_limit`.
	 */
	const SCHEDULED_CLEANUP_TIME_LIMIT = 5;

	/**
	 * How many nonces should be removed per batch during the `clean_all()` run.
	 */
	const CLEAN_ALL_LIMIT_PER_BATCH = 1000;

	/**
	 * Nonce lifetime in seconds.
	 */
	const LIFETIME = HOUR_IN_SECONDS;

	/**
	 * The nonces used during the request are stored here to keep them valid.
	 * The property is static to keep the nonces accessible between the `Nonce_Handler` instances.
	 *
	 * @var array
	 */
	private static $nonces_used_this_request = array();

	/**
	 * The database object.
	 *
	 * @var \wpdb
	 */
	private $db;

	/**
	 * Initializing the object.
	 */
	public function __construct() {
		global $wpdb;

		$this->db = $wpdb;
	}

	/**
	 * Scheduling the WP-cron cleanup event.
	 */
	public function init_schedule() {
		add_action( 'jetpack_clean_nonces', array( __CLASS__, 'clean_scheduled' ) );
		if ( ! wp_next_scheduled( 'jetpack_clean_nonces' ) ) {
			wp_schedule_event( time(), 'hourly', 'jetpack_clean_nonces' );
		}
	}

	/**
	 * Reschedule the WP-cron cleanup event to make it start sooner.
	 */
	public function reschedule() {
		wp_clear_scheduled_hook( 'jetpack_clean_nonces' );
		wp_schedule_event( time(), 'hourly', 'jetpack_clean_nonces' );
	}

	/**
	 * Adds a used nonce to a list of known nonces.
	 *
	 * @param int    $timestamp the current request timestamp.
	 * @param string $nonce the nonce value.
	 *
	 * @return bool whether the nonce is unique or not.
	 */
	public function add( $timestamp, $nonce ) {
		if ( isset( static::$nonces_used_this_request[ "$timestamp:$nonce" ] ) ) {
			return static::$nonces_used_this_request[ "$timestamp:$nonce" ];
		}

		// This should always have gone through Jetpack_Signature::sign_request() first to check $timestamp and $nonce.
		$timestamp = (int) $timestamp;
		$nonce     = esc_sql( $nonce );

		// Raw query so we can avoid races: add_option will also update.
		$show_errors = $this->db->hide_errors();

		// Running `try...finally` to make sure that we re-enable errors in case of an exception.
		try {
			$old_nonce = $this->db->get_row(
				$this->db->prepare( "SELECT 1 FROM `{$this->db->options}` WHERE option_name = %s", "jetpack_nonce_{$timestamp}_{$nonce}" )
			);

			if ( $old_nonce === null ) {
				$return = (bool) $this->db->query(
					$this->db->prepare(
						"INSERT INTO `{$this->db->options}` (`option_name`, `option_value`, `autoload`) VALUES (%s, %s, %s)",
						"jetpack_nonce_{$timestamp}_{$nonce}",
						time(),
						'no'
					)
				);
			} else {
				$return = false;
			}
		} finally {
			$this->db->show_errors( $show_errors );
		}

		static::$nonces_used_this_request[ "$timestamp:$nonce" ] = $return;

		return $return;
	}

	/**
	 * Removing all existing nonces, or at least as many as possible.
	 * Capped at 20 seconds to avoid breaking the site.
	 *
	 * @param int $cutoff_timestamp All nonces added before this timestamp will be removed.
	 * @param int $time_limit How long the cleanup can run (in seconds).
	 *
	 * @return true
	 */
	public function clean_all( $cutoff_timestamp = PHP_INT_MAX, $time_limit = 20 ) {
		// phpcs:ignore Generic.CodeAnalysis.ForLoopWithTestFunctionCall.NotAllowed
		for ( $end_time = time() + $time_limit; time() < $end_time; ) {
			$result = $this->delete( static::CLEAN_ALL_LIMIT_PER_BATCH, $cutoff_timestamp );

			if ( ! $result ) {
				break;
			}
		}

		return true;
	}

	/**
	 * Scheduled clean up of the expired nonces.
	 */
	public static function clean_scheduled() {
		/**
		 * Adjust the time limit for the scheduled cleanup.
		 *
		 * @since 9.5.0
		 *
		 * @param int $time_limit How long the cleanup can run (in seconds).
		 */
		$time_limit = apply_filters( 'jetpack_connection_nonce_cleanup_runtime_limit', static::SCHEDULED_CLEANUP_TIME_LIMIT );

		( new static() )->clean_all( time() - static::LIFETIME, $time_limit );
	}

	/**
	 * Delete the nonces.
	 *
	 * @param int      $limit How many nonces to delete.
	 * @param null|int $cutoff_timestamp All nonces added before this timestamp will be removed.
	 *
	 * @return int|false Number of removed nonces, or `false` if nothing to remove (or in case of a database error).
	 */
	public function delete( $limit = 10, $cutoff_timestamp = null ) {
		global $wpdb;

		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_id FROM `{$wpdb->options}`"
				. " WHERE `option_name` >= 'jetpack_nonce_' AND `option_name` < %s"
				. ' LIMIT %d',
				'jetpack_nonce_' . $cutoff_timestamp,
				$limit
			)
		);

		if ( ! is_array( $ids ) ) {
			// There's an error and we can't proceed.
			return false;
		}

		// Removing zeroes in case AUTO_INCREMENT of the options table is broken, and all ID's are zeroes.
		$ids = array_filter( $ids );

		if ( ! count( $ids ) ) {
			// There's nothing to remove.
			return false;
		}

		$ids_fill = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );

		$args   = $ids;
		$args[] = 'jetpack_nonce_%';

		// The Code Sniffer is unable to understand what's going on...
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		return $wpdb->query( $wpdb->prepare( "DELETE FROM `{$wpdb->options}` WHERE `option_id` IN ( {$ids_fill} ) AND option_name LIKE %s", $args ) );
	}

	/**
	 * Clean the cached nonces valid during the current request, therefore making them invalid.
	 *
	 * @return bool
	 */
	public static function invalidate_request_nonces() {
		static::$nonces_used_this_request = array();

		return true;
	}

}
