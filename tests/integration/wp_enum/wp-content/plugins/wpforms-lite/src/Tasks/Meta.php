<?php

namespace WPForms\Tasks;

/**
 * Class Meta helps to manage the tasks meta information
 * between Action Scheduler and WPForms hooks arguments.
 * We can't pass arguments longer than >191 chars in JSON to AS,
 * so we need to store them somewhere (and clean from time to time).
 *
 * @since 1.5.9
 */
class Meta extends \WPForms_DB {

	/**
	 * Primary key (unique field) for the database table.
	 *
	 * @since 1.5.9
	 *
	 * @var string
	 */
	public $primary_key = 'id';

	/**
	 * Database type identifier.
	 *
	 * @since 1.5.9
	 *
	 * @var string
	 */
	public $type = 'tasks_meta';

	/**
	 * Primary class constructor.
	 *
	 * @since 1.5.9
	 */
	public function __construct() {

		$this->table_name = self::get_table_name();
	}

	/**
	 * Get the DB table name.
	 *
	 * @since 1.5.9
	 *
	 * @return string
	 */
	public static function get_table_name() {

		global $wpdb;

		return $wpdb->prefix . 'wpforms_tasks_meta';
	}

	/**
	 * Get table columns.
	 *
	 * @since 1.5.9
	 */
	public function get_columns() {

		return [
			'id'     => '%d',
			'action' => '%s',
			'data'   => '%s',
			'date'   => '%s',
		];
	}

	/**
	 * Default column values.
	 *
	 * @since 1.5.9
	 *
	 * @return array
	 */
	public function get_column_defaults() {

		return [
			'action' => '',
			'data'   => '',
			'date'   => gmdate( 'Y-m-d H:i:s' ),
		];
	}

	/**
	 * Create custom entry meta database table.
	 * Used in migration and on plugin activation.
	 *
	 * @since 1.5.9
	 */
	public function create_table() {

		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = '';

		if ( ! empty( $wpdb->charset ) ) {
			$charset_collate .= "DEFAULT CHARACTER SET {$wpdb->charset}";
		}
		if ( ! empty( $wpdb->collate ) ) {
			$charset_collate .= " COLLATE {$wpdb->collate}";
		}

		$sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			action varchar(255) NOT NULL,
			data longtext NOT NULL,
			date datetime NOT NULL,
			PRIMARY KEY  (id)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Remove queue records for a defined period of time in the past.
	 * Calling this method will remove queue records that are older than $period seconds.
	 *
	 * @since 1.5.9
	 *
	 * @param string $action   Action that should be cleaned up.
	 * @param int    $interval Number of seconds from now.
	 *
	 * @return int Number of removed tasks meta records.
	 */
	public function clean_by( $action, $interval ) {

		global $wpdb;

		if ( empty( $action ) || empty( $interval ) ) {
			return 0;
		}

		$table  = self::get_table_name();
		$action = sanitize_key( $action );
		$date   = gmdate( 'Y-m-d H:i:s', time() - (int) $interval );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM `$table` WHERE action = %s AND date < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$action,
				$date
			)
		);
	}

	/**
	 * Inserts a new record into the database.
	 *
	 * @since 1.5.9
	 *
	 * @param array  $data Column data.
	 * @param string $type Optional. Data type context.
	 *
	 * @return int ID for the newly inserted record. 0 otherwise.
	 */
	public function add( $data, $type = '' ) {

		if ( empty( $data['action'] ) || ! is_string( $data['action'] ) ) {
			return 0;
		}

		$data['action'] = sanitize_key( $data['action'] );

		if ( isset( $data['data'] ) ) {
			$data['data'] = $this->prepare_data( $data['data'] );
		}

		if ( empty( $type ) ) {
			$type = $this->type;
		}

		return parent::add( $data, $type );
	}

	/**
	 * Prepare data.
	 *
	 * @since 1.7.0
	 *
	 * @param array $data Meta data.
	 *
	 * @return string
	 */
	private function prepare_data( $data ) {

		$string = wp_json_encode( $data );

		if ( $string === false ) {
			$string = '';
		}

		/*
		 * We are encoding the string representation of all the data
		 * to make sure that nothing can harm the database.
		 * This is not an encryption, and we need this data later as is,
		 * so we are using one of the fastest way to do that.
		 * This data is removed from DB on a daily basis.
		 */
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return base64_encode( $string );
	}

	/**
	 * Retrieve a row from the database based on a given row ID.
	 *
	 * @since 1.5.9
	 *
	 * @param int $meta_id Meta ID.
	 *
	 * @return null|object
	 */
	public function get( $meta_id ) {

		$meta = parent::get( $meta_id );

		if ( empty( $meta ) || empty( $meta->data ) ) {
			return $meta;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$decoded = base64_decode( $meta->data );

		if ( $decoded === false || ! is_string( $decoded ) ) {
			$meta->data = '';
		} else {
			$meta->data = json_decode( $decoded, true );
		}

		return $meta;
	}

	/**
	 * Get meta ID by action name and params.
	 *
	 * @since 1.7.0
	 *
	 * @param string $action Action name.
	 * @param array  $params Action params.
	 *
	 * @return int
	 */
	public function get_meta_id( $action, $params ) {

		global $wpdb;

		$table  = self::get_table_name();
		$action = sanitize_key( $action );
		$params = $this->prepare_data( array_values( $params ) );

		return absint(
			$wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->prepare(
					"SELECT id FROM `$table` WHERE action = %s AND data = %s LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$action,
					$params
				)
			)
		);
	}
}
