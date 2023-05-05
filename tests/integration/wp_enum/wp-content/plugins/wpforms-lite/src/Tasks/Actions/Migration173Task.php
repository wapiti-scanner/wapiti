<?php

namespace WPForms\Tasks\Actions;

use WPForms\Tasks\Meta;
use WPForms\Tasks\Task;
use WPForms\Tasks\Tasks;
use WPForms_Entry_Fields_Handler;
use WPForms_Entry_Handler;

/**
 * Class Migration173Task.
 *
 * @since 1.7.3
 */
class Migration173Task extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.7.3
	 */
	const ACTION = 'wpforms_process_migration_173';

	/**
	 * Status option name.
	 *
	 * @since 1.7.3
	 */
	const STATUS = 'wpforms_process_migration_173_status';

	/**
	 * Start status.
	 *
	 * @since 1.7.3
	 */
	const START = 'start';

	/**
	 * In progress status.
	 *
	 * @since 1.7.3
	 */
	const IN_PROGRESS = 'in progress';

	/**
	 * Completed status.
	 *
	 * @since 1.7.3
	 */
	const COMPLETED = 'completed';

	/**
	 * Chunk size to use.
	 * Specifies how many entries to load for scanning in one db request.
	 * Affects memory usage.
	 *
	 * @since 1.7.3
	 */
	const CHUNK_SIZE = 50;

	/**
	 * Entry handler.
	 *
	 * @since 1.7.3
	 *
	 * @var WPForms_Entry_Handler
	 */
	private $entry_handler;

	/**
	 * Entry fields handler.
	 *
	 * @since 1.7.3
	 *
	 * @var WPForms_Entry_Fields_Handler
	 */
	private $entry_fields_handler;

	/**
	 * Class constructor.
	 *
	 * @since 1.7.3
	 */
	public function __construct() {

		parent::__construct( self::ACTION );
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.7.3
	 */
	public function init() {

		$this->entry_handler        = wpforms()->get( 'entry' );
		$this->entry_fields_handler = wpforms()->get( 'entry_fields' );

		if ( ! $this->entry_handler || ! $this->entry_fields_handler ) {
			return;
		}

		// Bail out if migration is not started or completed.
		$status = get_option( self::STATUS );

		if ( ! $status || $status === self::COMPLETED ) {
			return;
		}

		// Mark that migration is in progress.
		update_option( self::STATUS, self::IN_PROGRESS );

		$this->hooks();

		$tasks = wpforms()->get( 'tasks' );

		// Add new if none exists.
		if ( $tasks->is_scheduled( self::ACTION ) !== false ) {
			return;
		}

		// Init migration.
		$this->init_migration( $tasks );
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		// Register the migrate action.
		add_action( self::ACTION, [ $this, 'migrate' ] );

		// Register after process queue action.
		add_action( 'action_scheduler_after_process_queue', [ $this, 'after_process_queue' ] );
	}

	/**
	 * Migrate an entry.
	 *
	 * @since 1.7.3
	 *
	 * @param int $meta_id Action meta id.
	 */
	public function migrate( $meta_id ) {

		$params = ( new Meta() )->get( $meta_id );

		if ( ! $params ) {
			return;
		}

		list( $entry_id_chunk ) = $params->data;

		foreach ( $entry_id_chunk as $entry_id ) {
			$this->save_entry( $entry_id );
		}
	}

	/**
	 * After process queue action.
	 * Set status as completed.
	 *
	 * @since 1.7.3
	 */
	public function after_process_queue() {

		if ( as_has_scheduled_action( self::ACTION ) ) {
			return;
		}

		// Mark that migration is finished.
		update_option( self::STATUS, self::COMPLETED );
	}

	/**
	 * Init migration.
	 *
	 * @since 1.7.3
	 *
	 * @param Tasks $tasks Tasks class instance.
	 */
	private function init_migration( $tasks ) {

		// This part of the migration shouldn't take more than 1 second even on big sites.
		$entry_ids = $this->get_legacy_entry_ids();

		if ( ! $entry_ids ) {
			// Mark that migration is completed.
			update_option( self::STATUS, self::COMPLETED );

			return;
		}

		/**
		 * This part of the migration can take a while.
		 * Saving hundreds of entries with a potentially very high number of entry fields could be time and memory consuming.
		 * That is why we perform save via Action Scheduler.
		 */
		$entry_id_chunks = array_chunk( $entry_ids, self::CHUNK_SIZE, true );

		foreach ( $entry_id_chunks as $entry_id_chunk ) {
			$tasks->create( self::ACTION )->async()->params( $entry_id_chunk )->register();
		}
	}

	/**
	 * Get entry ids which do not have relevant entry field records.
	 *
	 * @since 1.7.3
	 *
	 * @return int[]
	 */
	private function get_legacy_entry_ids() {

		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$entries = $wpdb->get_results(
			"
			SELECT e.entry_id FROM {$this->entry_handler->table_name} e
    			LEFT JOIN {$this->entry_fields_handler->table_name} ef
    				ON e.entry_id=ef.entry_id
            WHERE
                e.status IN( 'partial', 'abandoned' ) AND
            	ef.entry_id IS NULL"
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching

		if ( ! $entries || ! is_array( $entries ) ) {
			return [];
		}

		return array_map( 'intval', wp_list_pluck( $entries, 'entry_id' ) );
	}

	/**
	 * Save entry properly.
	 *
	 * @since 1.7.3
	 *
	 * @param int $entry_id Entry id.
	 */
	private function save_entry( $entry_id ) {

		$entry = $this->entry_handler->get( $entry_id );

		if ( ! $entry || ! isset( $entry->form_id, $entry->fields, $entry->date_modified ) ) {
			return;
		}

		$fields = json_decode( $entry->fields, true );

		if ( ! is_array( $fields ) ) {
			return;
		}

		$form_data = [
			'id'   => (int) $entry->form_id,
			'date' => $entry->date_modified,
		];

		$this->entry_fields_handler->save( $fields, $form_data, $entry_id, true );
	}
}
