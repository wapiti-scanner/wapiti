<?php

namespace WPForms\Tasks\Actions;

use WPForms\Tasks\Task;
use WPForms\Tasks\Meta;

/**
 * Class EntryEmailsMetaCleanupTask.
 *
 * @since 1.5.9
 */
class EntryEmailsMetaCleanupTask extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.5.9
	 */
	const ACTION = 'wpforms_process_entry_emails_meta_cleanup';

	/**
	 * Class constructor.
	 *
	 * @since 1.5.9
	 */
	public function __construct() {

		parent::__construct( self::ACTION );

		$this->init();
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.5.9
	 */
	public function init() {

		// Register the action handler.
		$this->hooks();

		$tasks = wpforms()->get( 'tasks' );

		$email_async = wpforms_setting( 'email-async' );

		// Add new if none exists.
		if ( $tasks->is_scheduled( self::ACTION ) !== false ) {
			// Cancel scheduled action if email async option is not set.
			if ( ! $email_async ) {
				$this->cancel();
			}

			return;
		}

		// Do not schedule action if email async option is not set.
		if ( ! $email_async ) {
			return;
		}

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		/**
		 * Filters the email cleanup task interval.
		 *
		 * @since 1.5.9
		 *
		 * @param int $interval Interval in seconds.
		 */
		$interval = (int) apply_filters( 'wpforms_tasks_entry_emails_meta_cleanup_interval', DAY_IN_SECONDS );
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		$this->recurring( strtotime( 'tomorrow' ), $interval )
		     ->params( $interval )
		     ->register();
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
	 * Perform the cleanup action: remove outdated meta for entry emails task.
	 *
	 * @since 1.5.9
	 *
	 * @param int $meta_id ID for meta information for a task.
	 */
	public function process( $meta_id ) {

		$task_meta = new Meta();
		$meta      = $task_meta->get( (int) $meta_id );

		// We should actually receive something.
		if ( empty( $meta ) || empty( $meta->data ) ) {
			return;
		}

		list( $interval ) = $meta->data;

		$task_meta->clean_by( EntryEmailsTask::ACTION, (int) $interval );
	}
}
