<?php
/**
 * A class that handles the notices for the Stats Admin dashboard.
 *
 * @package automattic/jetpack-stats-admin
 */

namespace Automattic\Jetpack\Stats_Admin;

use Automattic\Jetpack\Stats\Options as Stats_Options;

/**
 * The Notices class handles the notices for the Stats Admin dashboard.
 *
 * @package Automattic\Jetpack\Stats_Admin
 */
class Notices {
	const OPT_OUT_NEW_STATS_NOTICE_ID  = 'opt_out_new_stats';
	const NEW_STATS_FEEDBACK_NOTICE_ID = 'new_stats_feedback';
	const OPT_IN_NEW_STATS_NOTICE_ID   = 'opt_in_new_stats';

	const NOTICE_STATUS_DISMISSED = 'dismissed';
	const NOTICE_STATUS_POSTPONED = 'postponed';

	const VIEWS_TO_SHOW_FEEDBACK      = 3;
	const POSTPONE_FEEDBACK_DAYS      = 30;
	const POSTPONE_OPT_IN_NOTICE_DAYS = 30;

	/**
	 * Update the notice status.
	 *
	 * @param mixed $id ID of the notice.
	 * @param mixed $status Status of the notice.
	 * @param int   $postponed_for Postponed for how many seconds.
	 * @return bool
	 */
	public function update_notice( $id, $status, $postponed_for = 0 ) {
		$notices        = Stats_Options::get_option( 'notices' );
		$notices[ $id ] = array(
			'status'       => $status,
			'id'           => $id,
			'dismissed_at' => time(),
		);
		// Set the next show time if the notice is postponed.
		if ( $status === self::NOTICE_STATUS_POSTPONED ) {
			$notices[ $id ]['next_show_at'] = time() + ( $postponed_for > 0 ? $postponed_for : self::POSTPONE_FEEDBACK_DAYS * DAY_IN_SECONDS );
		}
		return Stats_Options::set_option( 'notices', $notices );
	}

	/**
	 * Return an array of notices IDs as keys and their value to flag whther to show them.
	 *
	 * @return array
	 */
	public function get_notices_to_show() {
		$new_stats_enabled        = Stats_Options::get_option( 'enable_odyssey_stats' );
		$stats_views              = $this->get_new_stats_views();
		$odyssey_stats_changed_at = intval( Stats_Options::get_option( 'odyssey_stats_changed_at' ) );

		return array(
			// Show Opt-in notice 30 days after the new stats being disabled.
			self::OPT_IN_NEW_STATS_NOTICE_ID   => ! $new_stats_enabled
				&& $odyssey_stats_changed_at < time() - self::POSTPONE_OPT_IN_NOTICE_DAYS * DAY_IN_SECONDS
				&& ! $this->is_notice_hidden( self::OPT_IN_NEW_STATS_NOTICE_ID ),

			// Show feedback notice after 3 views of the new stats.
			self::NEW_STATS_FEEDBACK_NOTICE_ID => $new_stats_enabled
				&& $stats_views >= self::VIEWS_TO_SHOW_FEEDBACK
				&& ! $this->is_notice_hidden( self::NEW_STATS_FEEDBACK_NOTICE_ID ),

			// Show opt-out notice before 3 views of the new stats, where 3 is included.
			self::OPT_OUT_NEW_STATS_NOTICE_ID  => $new_stats_enabled
				&& $stats_views < self::VIEWS_TO_SHOW_FEEDBACK
				&& ! $this->is_notice_hidden( self::OPT_OUT_NEW_STATS_NOTICE_ID ),
		);
	}

	/**
	 * Returns the array of hidden notices.
	 *
	 * @return array Array of hidden notices.
	 */
	public function get_hidden_notices() {
		$notices = Stats_Options::get_option( 'notices' );

		$hidden_notices = array_filter(
			$notices,
			function ( $notice ) {
				if ( ! isset( $notice['status'] ) ) {
					return false;
				}
				switch ( $notice['status'] ) {
					case self::NOTICE_STATUS_DISMISSED:
						return true;
					case self::NOTICE_STATUS_POSTPONED:
						return empty( $notice['next_show_at'] ) || $notice['next_show_at'] > time();
					default:
						return false;
				}
			},
			ARRAY_FILTER_USE_BOTH
		);

		return $hidden_notices;
	}

	/**
	 * Checks if a notice is hidden.
	 *
	 * @param mixed $id ID of the notice.
	 * @return bool
	 */
	public function is_notice_hidden( $id ) {
		return array_key_exists( $id, $this->get_hidden_notices() );
	}

	/**
	 * Returns the number of views of the new stats dashboard.
	 */
	public function get_new_stats_views() {
		return Stats_Options::get_option( 'views' );
	}
}
