<?php

namespace WPForms\Emails;

use WPForms\Tasks\Task;

/**
 * Action Scheduler task to fetch and cache Email Summaries Info Blocks.
 *
 * @since 1.6.4
 */
class FetchInfoBlocksTask extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.6.4
	 */
	const ACTION = 'wpforms_email_summaries_fetch_info_blocks';

	/**
	 * Option name to store the timestamp of the last run.
	 *
	 * @since 1.6.4
	 */
	const LAST_RUN = 'wpforms_email_summaries_fetch_info_blocks_last_run';

	/**
	 * Class constructor.
	 *
	 * @since 1.6.4
	 */
	public function __construct() {

		parent::__construct( self::ACTION );

		$this->init();
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.6.4
	 */
	public function init() {

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

		// Register the action handler.
		add_action( self::ACTION, [ $this, 'process' ] );
	}

	/**
	 * Randomly pick a timestamp which is not more than 1 week in the future
	 * starting before Email Summaries dispatch happens.
	 *
	 * @since 1.6.4
	 *
	 * @return int
	 */
	private function generate_start_date() {

		$tracking = [];

		$tracking['days']    = wp_rand( 0, 6 ) * DAY_IN_SECONDS;
		$tracking['hours']   = wp_rand( 0, 23 ) * HOUR_IN_SECONDS;
		$tracking['minutes'] = wp_rand( 0, 59 ) * MINUTE_IN_SECONDS;
		$tracking['seconds'] = wp_rand( 0, 59 );

		return strtotime( 'previous monday 1pm' ) + array_sum( $tracking );
	}

	/**
	 * Process the task.
	 *
	 * @since 1.6.4
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

		( new InfoBlocks() )->cache_all();

		// Update the last run option to the current timestamp.
		update_option( self::LAST_RUN, time() );
	}
}
