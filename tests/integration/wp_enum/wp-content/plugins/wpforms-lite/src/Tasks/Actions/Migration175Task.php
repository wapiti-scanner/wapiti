<?php

namespace WPForms\Tasks\Actions;

use WPForms\Tasks\Task;
use WPForms\Tasks\Tasks;
use WPForms_Entry_Handler;
use WPForms_Entry_Meta_Handler;

/**
 * Class Migration175Task.
 *
 * @since 1.7.5
 */
class Migration175Task extends Task {

	/**
	 * Action name for this task.
	 *
	 * @since 1.7.5
	 */
	const ACTION = 'wpforms_process_migration_175';

	/**
	 * Status option name.
	 *
	 * @since 1.7.5
	 */
	const STATUS = 'wpforms_process_migration_175_status';

	/**
	 * Start status.
	 *
	 * @since 1.7.5
	 */
	const START = 'start';

	/**
	 * In progress status.
	 *
	 * @since 1.7.5
	 */
	const IN_PROGRESS = 'in progress';

	/**
	 * Completed status.
	 *
	 * @since 1.7.5
	 */
	const COMPLETED = 'completed';

	/**
	 * Chunk size to use.
	 * Specifies how many entries to convert in one db request.
	 *
	 * @since 1.7.5
	 */
	const CHUNK_SIZE = 5000;

	/**
	 * Chunk size of the migration task.
	 * Specifies how many entry ids to load at once for further conversion.
	 *
	 * @since 1.7.5
	 */
	const TASK_CHUNK_SIZE = self::CHUNK_SIZE * 10;

	/**
	 * Entry handler.
	 *
	 * @since 1.7.5
	 *
	 * @var WPForms_Entry_Handler
	 */
	private $entry_handler;

	/**
	 * Entry meta handler.
	 *
	 * @since 1.7.5
	 *
	 * @var WPForms_Entry_Meta_Handler
	 */
	private $entry_meta_handler;

	/**
	 * Temporary table name.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	private $temp_table_name;

	/**
	 * Class constructor.
	 *
	 * @since 1.7.5
	 */
	public function __construct() {

		parent::__construct( self::ACTION );
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.7.5
	 */
	public function init() {

		global $wpdb;

		$this->entry_handler      = wpforms()->get( 'entry' );
		$this->entry_meta_handler = wpforms()->get( 'entry_meta' );
		$this->temp_table_name    = "{$wpdb->prefix}wpforms_temp_entry_ids";

		if ( ! $this->entry_handler || ! $this->entry_meta_handler ) {
			return;
		}

		// Bail out if migration is not started or completed.
		$status = get_option( self::STATUS );

		if ( ! $status || $status === self::COMPLETED ) {
			return;
		}

		$this->hooks();

		if ( $status === self::START ) {
			// Mark that migration is in progress.
			update_option( self::STATUS, self::IN_PROGRESS );

			// Alter entry meta table.
			$this->alter_entry_meta_table();

			// Init migration.
			$this->init_migration();
		}
	}

	/**
	 * Modify field in the entry meta table.
	 *
	 * @since 1.7.5
	 */
	private function alter_entry_meta_table() {

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "ALTER TABLE {$this->entry_meta_handler->table_name} MODIFY type VARCHAR(255)" );
	}

	/**
	 * Add index to a table.
	 *
	 * @since 1.7.5
	 *
	 * @param string $table_name Table.
	 * @param string $index_name Index name.
	 * @param string $key_part   Key part.
	 *
	 * @return void
	 */
	private function add_index( $table_name, $index_name, $key_part ) {

		global $wpdb;

		// Check id index already exists.
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->get_var(
			"SELECT COUNT(1) IndexIsThere
					FROM INFORMATION_SCHEMA.STATISTICS
					WHERE table_schema = DATABASE()
      					AND table_name = '$table_name'
          				AND index_name = '$index_name'"
		);

		if ( $result === '1' ) {
			return;
		}

		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Change the column length for the wp_wpforms_entry_meta.type column to 255 and add an index.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( "CREATE INDEX $index_name ON $table_name ( $key_part )" );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.7.5
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
	 * @param int $action_index Action index.
	 *
	 * @since 1.7.5
	 */
	public function migrate( $action_index ) {

		global $wpdb;

		$db_indexes = [
			- 3 => [
				'table_name' => $this->entry_meta_handler->table_name,
				'index_name' => 'form_id',
				'key_part'   => 'form_id',
			],
			- 2 => [
				'table_name' => $this->entry_meta_handler->table_name,
				'index_name' => 'type',
				'key_part'   => 'type',
			],
			- 1 => [
				'table_name' => $this->entry_meta_handler->table_name,
				'index_name' => 'data',
				'key_part'   => 'data(32)',
			],
		];

		// We create indexes in the background as it could take significant time on big database.
		if ( array_key_exists( $action_index, $db_indexes ) ) {
			$this->add_index(
				$db_indexes[ $action_index ]['table_name'],
				$db_indexes[ $action_index ]['index_name'],
				$db_indexes[ $action_index ]['key_part']
			);

			return;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching

		// The query length in migrate_payment_data() is about 500 chars for 1 entry (7 metas).
		// The length of the query is defined by MAX_ALLOWED_PACKET variable, which defaults to 4 MB on MySQL 5.7.
		// We increase MAX_ALLOWED_PACKET variable to fit number of entries specified in self::CHUNK_SIZE.
		$new_max_allowed_packet = 500 * self::CHUNK_SIZE;
		$max_allowed_packet     = (int) $wpdb->get_var( "SHOW VARIABLES LIKE 'MAX_ALLOWED_PACKET'", 1 );

		if ( $new_max_allowed_packet > $max_allowed_packet ) {
			$wpdb->query( "SET MAX_ALLOWED_PACKET = $new_max_allowed_packet" );
		}

		// Using OFFSET makes a way longer request, as MySQL has to access all rows before OFFSET.
		// We follow very fast way with indexed column (id > $action_index).
		$entry_ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT entry_id FROM $this->temp_table_name
                WHERE id > %d LIMIT %d",
				$action_index,
				self::TASK_CHUNK_SIZE
			)
		);

		$i               = 0;
		$entry_ids_count = count( $entry_ids );

		// This cycle is twice less memory consuming than array_chunk( $entry_ids ).
		while ( $i < $entry_ids_count ) {
			$entry_ids_chunk = array_slice( $entry_ids, $i, self::CHUNK_SIZE );

			$this->migrate_payment_data( implode( ',', $entry_ids_chunk ) );

			$i += self::CHUNK_SIZE;
		}

		if ( $new_max_allowed_packet > $max_allowed_packet ) {
			$wpdb->query( "SET MAX_ALLOWED_PACKET = $max_allowed_packet" );
		}
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * After process queue action.
	 * Set status as completed.
	 *
	 * @since 1.7.5
	 */
	public function after_process_queue() {

		$tasks = wpforms()->get( 'tasks' );

		if ( ! $tasks || $tasks->is_scheduled( self::ACTION ) ) {
			return;
		}

		$this->drop_temp_table();

		// Mark that migration is finished.
		update_option( self::STATUS, self::COMPLETED );
	}

	/**
	 * Init migration.
	 *
	 * @since 1.7.5
	 */
	private function init_migration() {

		// Get all payment entries.
		$count = $this->get_unprocessed_payment_entry_ids();

		if ( ! $count ) {
			$this->drop_temp_table();
		}

		// We need 3 preliminary steps to create indexes.
		$index = - 3;

		while ( $index < $count ) {
			// We do not use Task class here as we do not need meta. So, we reduce number of DB requests.
			as_enqueue_async_action(
				self::ACTION,
				[ $index ],
				Tasks::GROUP
			);

			$index = $index < 0 ? $index + 1 : $index + self::CHUNK_SIZE;
		}
	}

	/**
	 * Migrate payment data to the correct table.
	 *
	 * @param string $entry_ids_list List of entry ids.
	 *
	 * @since 1.7.5
	 */
	private function migrate_payment_data( $entry_ids_list ) {

		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			"SELECT entry_id, form_id, user_id, status, meta, date
					FROM {$this->entry_handler->table_name}
					WHERE entry_id IN ( $entry_ids_list )"
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching

		$values = [];

		foreach ( $wpdb->last_result as $entry ) {
			$meta = json_decode( $entry->meta, true );

			if ( ! is_array( $meta ) ) {
				continue;
			}

			foreach ( $meta as $meta_key => $meta_value ) {
				// If meta_key doesn't begin with `payment_`, prefix it.
				$meta_key = strpos( $meta_key, 'payment_' ) === 0 ? $meta_key : "payment_$meta_key";

				// We do not use $wpdb->prepare here, as it is 5 times slower.
				// Prepare takes 1.3 sec to prepare 1000 entries (6000 meta records).
				// It is incomparable with the two queries here.
				// With sprintf, total processing time of this method is 0.15 sec for 1000 entries.
				$values[] = sprintf(
					"( %d, %d, %d, '%s', '%s', '%s', '%s' )",
					$entry->entry_id,
					$entry->form_id,
					$entry->user_id,
					$entry->status,
					$meta_key,
					$meta_value,
					$entry->date
				);
			}
		}

		$values = implode( ', ', $values );

		// The following query length is about 500 chars for 1 entry (7 metas).

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			"INSERT INTO {$this->entry_meta_handler->table_name}
						( entry_id, form_id, user_id, status, type, data, date )
						VALUES $values"
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Get entry ids which do not have relevant entry field records.
	 * Store them in a temporary table.
	 *
	 * @since 1.7.5
	 *
	 * @return int
	 */
	private function get_unprocessed_payment_entry_ids() {

		global $wpdb;

		$this->drop_temp_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			"CREATE TABLE $this->temp_table_name
				(
				    id       BIGINT AUTO_INCREMENT PRIMARY KEY,
				    entry_id BIGINT NOT NULL
				)"
		);

		$wpdb->query(
			"INSERT INTO $this->temp_table_name (entry_id)
				SELECT entry_id
				FROM {$this->entry_handler->table_name}
				WHERE type = 'payment'
				  AND entry_id NOT IN
				      (SELECT entry_id FROM {$this->entry_meta_handler->table_name} WHERE type LIKE 'payment_%')"
		);

		return $wpdb->rows_affected;
	}

	/**
	 * Drop temporary table.
	 *
	 * @since 1.7.5
	 */
	private function drop_temp_table() {

		global $wpdb;

		$wpdb->query( "DROP TABLE IF EXISTS $this->temp_table_name" );
	}
}
