<?php

namespace WPForms\Integrations\UsageTracking;

use WPForms\Tasks\Task;

/**
 * Class SendUsageTask.
 *
 * @since 1.6.1
 */
class SendUsageTask extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.6.1
	 */
	const ACTION = 'wpforms_send_usage_data';

	/**
	 * Server URL to send requests to.
	 *
	 * @since 1.6.1
	 */
	const TRACK_URL = 'https://wpformsusage.com/v1/track';

	/**
	 * Option name to store the timestamp of the last run.
	 *
	 * @since 1.6.3
	 */
	const LAST_RUN = 'wpforms_send_usage_last_run';

	/**
	 * Class constructor.
	 *
	 * @since 1.6.1
	 */
	public function __construct() {

		parent::__construct( self::ACTION );

		$this->init();
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.6.1
	 */
	public function init() {

		// Register the action handler.
		$this->hooks();

		$tasks = wpforms()->get( 'tasks' );

		// Add new if none exists.
		if ( $tasks->is_scheduled( self::ACTION ) !== false ) {
			return;
		}

		$this->recurring( $this->generate_start_date(), WEEK_IN_SECONDS )->register();
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		add_action( self::ACTION, [ $this, 'process' ] );
	}

	/**
	 * Randomly pick a timestamp
	 * which is not more than 1 week in the future
	 * starting from next sunday.
	 *
	 * @since 1.6.1
	 *
	 * @return int
	 */
	private function generate_start_date() {

		$tracking = [];

		$tracking['days']    = wp_rand( 0, 6 ) * DAY_IN_SECONDS;
		$tracking['hours']   = wp_rand( 0, 23 ) * HOUR_IN_SECONDS;
		$tracking['minutes'] = wp_rand( 0, 59 ) * MINUTE_IN_SECONDS;
		$tracking['seconds'] = wp_rand( 0, 59 );

		return strtotime( 'next sunday' ) + array_sum( $tracking );
	}

	/**
	 * Send the actual data in a POST request.
	 *
	 * @since 1.6.1
	 */
	public function process() {

		$last_run = get_option( self::LAST_RUN );

		// Make sure we do not run it more than once a day.
		if (
			$last_run !== false &&
			( time() - $last_run ) < DAY_IN_SECONDS
		) {
			return;
		}

		// Send data to the usage tracking API.
		$ut = new UsageTracking();

		wp_remote_post(
			self::TRACK_URL,
			[
				'timeout'     => 5,
				'redirection' => 5,
				'httpversion' => '1.1',
				'blocking'    => true,
				'body'        => $ut->get_data(),
				'user-agent'  => $ut->get_user_agent(),
			]
		);

		// Update the last run option to the current timestamp.
		update_option( self::LAST_RUN, time() );
	}
}
