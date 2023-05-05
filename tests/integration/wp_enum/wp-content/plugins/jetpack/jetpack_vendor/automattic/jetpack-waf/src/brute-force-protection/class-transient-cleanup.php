<?php
/**
 * Adapted from Purge Transients by Seebz
 * https://github.com/Seebz/Snippets/tree/master/Wordpress/plugins/purge-transients
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf\Brute_Force_Protection;

/**
 * Transient Cleanup class.
 */
class Brute_Force_Protection_Transient_Cleanup {
	/**
	 * Jetpack Purge Transients.
	 *
	 * @access public
	 * @param string $older_than (default: '1 hour') Older Than.
	 */
	public static function jp_purge_transients( $older_than = '1 hour' ) {
		global $wpdb;
		$older_than_time = strtotime( '-' . $older_than );
		if ( $older_than_time > time() || $older_than_time < 1 ) {
			return false;
		}
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.LikeWildcardsInQuery
			"SELECT REPLACE(option_name, '_transient_timeout_jpp_', '') AS transient_name FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_jpp\__%%' AND option_value < %d",
			$older_than_time
		);
		$transients    = $wpdb->get_col( $sql ); // phpcs:ignore WordPress.DB -- $sql is prepared above.
		$options_names = array();
		foreach ( $transients as $transient ) {
			$options_names[] = '_transient_jpp_' . $transient;
			$options_names[] = '_transient_timeout_jpp_' . $transient;
		}
		if ( $options_names ) {
			$option_names_string = implode( ', ', array_fill( 0, count( $options_names ), '%s' ) );
			$result              = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name IN ($option_names_string)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- the placeholders are set above.
					$options_names
				)
			);
			if ( ! $result ) {
				return false;
			}
		}
	}

	/**
	 * Jetpack Purge Transients Activation.
	 *
	 * @access public
	 * @return void
	 */
	public static function jp_purge_transients_activation() {
		if ( ! wp_next_scheduled( 'jp_purge_transients_cron' ) ) {
			wp_schedule_event( time(), 'daily', 'jp_purge_transients_cron' );
		}
	}
}
