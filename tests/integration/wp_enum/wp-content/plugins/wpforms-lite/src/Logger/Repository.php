<?php

namespace WPForms\Logger;

/**
 * Class Repository.
 *
 * @since 1.6.3
 */
class Repository {

	/**
	 * Cache key name for total logs.
	 *
	 * @since 1.6.3
	 */
	const CACHE_TOTAL_KEY = 'wpforms_logs_total';

	/**
	 * Records query.
	 *
	 * @since 1.6.3
	 *
	 * @var \WPForms\Logger\RecordQuery
	 */
	private $records_query;

	/**
	 * Records.
	 *
	 * @since 1.6.3
	 *
	 * @var \WPForms\Logger\Records
	 */
	private $records;

	/**
	 * Get not-limited total query.
	 *
	 * @since 1.6.4.1
	 *
	 * @var int
	 */
	private $full_total;

	/**
	 * Log constructor.
	 *
	 * @since 1.6.3
	 *
	 * @param \WPForms\Logger\RecordQuery $records_query Records query.
	 */
	public function __construct( $records_query ) {

		$this->records_query = $records_query;
		$this->full_total    = false;
		$this->records       = new Records();
	}

	/**
	 * Get log table name.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	public static function get_table_name() {

		global $wpdb;

		return $wpdb->prefix . 'wpforms_logs';
	}

	/**
	 * Create table for database.
	 *
	 * @since 1.6.3
	 */
	public function create_table() {

		global $wpdb;

		$table = self::get_table_name();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			message LONGTEXT NOT NULL,
			types VARCHAR(255) NOT NULL,
			create_at DATETIME NOT NULL,
			form_id BIGINT(20),
			entry_id BIGINT(20),
			user_id BIGINT(20),
			PRIMARY KEY (id)
		) {$charset_collate};";

		maybe_create_table( $table, $sql );
	}

	/**
	 * Create new record.
	 *
	 * @since 1.6.3
	 *
	 * @param string       $title    Record title.
	 * @param string       $message  Record message.
	 * @param array|string $types    Array, string, or string separated by commas types.
	 * @param int          $form_id  Record form ID.
	 * @param int          $entry_id Record entry ID.
	 * @param int          $user_id  Record user ID.
	 */
	public function add( $title, $message, $types, $form_id, $entry_id, $user_id ) {

		$this->records->push(
			Record::create( $title, $message, $types, $form_id, $entry_id, $user_id )
		);
	}

	/**
	 * Get records.
	 *
	 * @since 1.6.3
	 *
	 * @param int    $limit  Query limit of records.
	 * @param int    $offset Offset of records.
	 * @param string $search Search.
	 * @param string $type   Type of records.
	 *
	 * @return \WPForms\Logger\Records
	 */
	public function records( $limit, $offset = 0, $search = '', $type = '' ) {

		$data             = $this->records_query->get( $limit, $offset, $search, $type );
		$this->full_total = true;
		$records          = new Records();
		// As we got raw data we need to convert to Record.
		foreach ( $data as $row ) {
			$records->push(
				$this->prepare_record( $row )
			);
		}

		return $records;
	}

	/**
	 * Get record.
	 *
	 * @since 1.6.3
	 *
	 * @param int $id Record ID.
	 *
	 * @return \WPForms\Logger\Record|null
	 */
	public function record( $id ) {

		global $wpdb;
		//phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$item = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . self::get_table_name() . ' WHERE id = %d', //phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
				absint( $id )
			)
		);
		if ( $item ) {
			$item = $this->prepare_record( $item );
		}

		return $item;
	}

	/**
	 * Create record from DB row.
	 *
	 * @since 1.6.3
	 *
	 * @param object $row Row from DB.
	 *
	 * @return \WPForms\Logger\Record
	 */
	private function prepare_record( $row ) {

		return new Record(
			absint( $row->id ),
			$row->title,
			$row->message,
			$row->types,
			$row->create_at,
			absint( $row->form_id ),
			absint( $row->entry_id ),
			absint( $row->user_id )
		);
	}

	/**
	 * Save records to database.
	 *
	 * @since 1.6.3
	 */
	public function save() {

		// We can't use the empty function because it doesn't work with Countable object.
		if ( ! count( $this->records ) ) {
			return;
		}
		global $wpdb;
		$sql = 'INSERT INTO ' . self::get_table_name() . ' ( `id`, `title`, `message`, `types`, `create_at`, `form_id`, `entry_id`, `user_id` ) VALUES ';
		foreach ( $this->records as $record ) {
			$sql .= $wpdb->prepare(
				'( NULL, %s, %s, %s, %s, %d, %d, %d ),',
				$record->get_title(),
				$record->get_message(),
				implode( ',', $record->get_types() ),
				$record->get_date( 'sql' ),
				$record->get_form_id(),
				$record->get_entry_id(),
				$record->get_user_id()
			);
		}
		$sql = rtrim( $sql, ',' );

		//phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( $sql );
		//phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
		wp_cache_delete( self::CACHE_TOTAL_KEY );
	}

	/**
	 * Check if the database table exist.
	 *
	 * @since 1.6.4
	 *
	 * @return bool
	 */
	public function table_exists() {

		global $wpdb;

		$table = self::get_table_name();

		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table; // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Get total count of logs.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_total() {

		global $wpdb;

		$total = wp_cache_get( self::CACHE_TOTAL_KEY );
		if ( ! $total ) {
			//phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
			$total = $this->full_total ? $wpdb->get_var( 'SELECT FOUND_ROWS()' ) : $wpdb->get_var( 'SELECT COUNT(ID) FROM ' . self::get_table_name() );
			//phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
			wp_cache_set( self::CACHE_TOTAL_KEY, $total, 'wpforms', DAY_IN_SECONDS );
		}

		return absint( $total );
	}

	/**
	 * Clear all records in Database.
	 *
	 * @since 1.6.3
	 */
	public function clear_all() {

		global $wpdb;

		//phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'TRUNCATE TABLE ' . self::get_table_name() );
		//phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
	}

}
