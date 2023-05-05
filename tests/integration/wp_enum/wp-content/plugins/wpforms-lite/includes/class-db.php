<?php

/**
 * DB class.
 *
 * This handy class originated from Pippin's Easy Digital Downloads.
 * https://github.com/easydigitaldownloads/easy-digital-downloads/blob/master/includes/class-edd-db.php
 *
 * Sub-classes should define $table_name, $version, and $primary_key in __construct() method.
 *
 * @since 1.1.6
 */
abstract class WPForms_DB {

	/**
	 * Database table name.
	 *
	 * @since 1.1.6
	 *
	 * @var string
	 */
	public $table_name;

	/**
	 * Database version.
	 *
	 * @since 1.1.6
	 *
	 * @var string
	 */
	public $version;

	/**
	 * Primary key (unique field) for the database table.
	 *
	 * @since 1.1.6
	 *
	 * @var string
	 */
	public $primary_key;

	/**
	 * Database type identifier.
	 *
	 * @since 1.5.1
	 *
	 * @var string
	 */
	public $type;

	/**
	 * Retrieve the list of columns for the database table.
	 * Sub-classes should define an array of columns here.
	 *
	 * @since 1.1.6
	 *
	 * @return array List of columns.
	 */
	public function get_columns() {

		return [];
	}

	/**
	 * Retrieve column defaults.
	 * Sub-classes can define default for any/all of columns defined in the get_columns() method.
	 *
	 * @since 1.1.6
	 *
	 * @return array All defined column defaults.
	 */
	public function get_column_defaults() {

		return [];
	}

	/**
	 * Retrieve a row from the database based on a given row ID.
	 *
	 * @since 1.1.6
	 *
	 * @param int $row_id Row ID.
	 *
	 * @return null|object
	 */
	public function get( $row_id ) {

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $this->table_name WHERE $this->primary_key = %d LIMIT 1;", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				(int) $row_id
			)
		);
	}

	/**
	 * Retrieve a row based on column and row ID.
	 *
	 * @since 1.1.6
	 *
	 * @param string     $column Column name.
	 * @param int|string $value  Column value.
	 *
	 * @return object|null Database query result, object or null on failure.
	 */
	public function get_by( $column, $value ) {

		global $wpdb;

		if (
			empty( $value ) ||
		    ! array_key_exists( $column, $this->get_columns() )
		) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $this->table_name WHERE $column = %s LIMIT 1;", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$value
			)
		);
	}

	/**
	 * Retrieve a value based on column name and row ID.
	 *
	 * @since 1.1.6
	 *
	 * @param string     $column Column name.
	 * @param int|string $row_id Row ID.
	 *
	 * @return string|null Database query result (as string), or null on failure.
	 */
	public function get_column( $column, $row_id ) {

		global $wpdb;

		if ( empty( $row_id ) || ! array_key_exists( $column, $this->get_columns() ) ) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var(
			$wpdb->prepare(
				"SELECT $column FROM $this->table_name WHERE $this->primary_key = %d LIMIT 1;", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				(int) $row_id
			)
		);
	}

	/**
	 * Retrieve one column value based on another given column and matching value.
	 *
	 * @since 1.1.6
	 *
	 * @param string $column       Column name.
	 * @param string $column_where Column to match against in the WHERE clause.
	 * @param string $column_value Value to match to the column in the WHERE clause.
	 *
	 * @return string|null Database query result (as string), or null on failure.
	 */
	public function get_column_by( $column, $column_where, $column_value ) {

		global $wpdb;

		if (
			empty( $column ) ||
			empty( $column_where ) ||
			empty( $column_value ) ||
			! array_key_exists( $column_where, $this->get_columns() ) ||
			! array_key_exists( $column, $this->get_columns() )
		) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var(
			$wpdb->prepare(
				"SELECT $column FROM $this->table_name WHERE $column_where = %s LIMIT 1;", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$column_value
			)
		);
	}

	/**
	 * Insert a new record into the database.
	 *
	 * @since 1.1.6
	 *
	 * @param array  $data Column data.
	 * @param string $type Optional. Data type context.
	 *
	 * @return int ID for the newly inserted record. 0 otherwise.
	 */
	public function add( $data, $type = '' ) {

		global $wpdb;

		// Set default values.
		$data = (array) wp_parse_args( $data, $this->get_column_defaults() );

		do_action( 'wpforms_pre_insert_' . $type, $data );

		// Initialise column format array.
		$column_formats = $this->get_columns();

		// Force fields to lower case.
		$data = array_change_key_case( $data );

		// White list columns.
		$data = array_intersect_key( $data, $column_formats );

		// Reorder $column_formats to match the order of columns given in $data.
		$data_keys      = array_keys( $data );
		$column_formats = array_merge( array_flip( $data_keys ), $column_formats );

		$wpdb->insert( $this->table_name, $data, $column_formats );

		do_action( 'wpforms_post_insert_' . $type, $wpdb->insert_id, $data );

		return $wpdb->insert_id;
	}

	/**
	 * Insert a new record into the database. This runs the add() method.
	 *
	 * @see add()
	 *
	 * @since 1.1.6
	 *
	 * @param array $data Column data.
	 *
	 * @return int ID for the newly inserted record.
	 */
	public function insert( $data ) {

		return $this->add( $data );
	}

	/**
	 * Update an existing record in the database.
	 *
	 * @since 1.1.6
	 *
	 * @param int|string $row_id Row ID for the record being updated.
	 * @param array      $data   Optional. Array of columns and associated data to update. Default empty array.
	 * @param string     $where  Optional. Column to match against in the WHERE clause. If empty, $primary_key
	 *                           will be used. Default empty.
	 * @param string     $type   Optional. Data type context, e.g. 'affiliate', 'creative', etc. Default empty.
	 *
	 * @return bool False if the record could not be updated, true otherwise.
	 */
	public function update( $row_id, $data = [], $where = '', $type = '' ) {

		global $wpdb;

		// Row ID must be a positive integer.
		$row_id = absint( $row_id );

		if ( empty( $row_id ) ) {
			return false;
		}

		if ( empty( $where ) ) {
			$where = $this->primary_key;
		}

		do_action( 'wpforms_pre_update_' . $type, $data );

		// Initialise column format array.
		$column_formats = $this->get_columns();

		// Force fields to lower case.
		$data = array_change_key_case( $data );

		// White list columns.
		$data = array_intersect_key( $data, $column_formats );

		// Reorder $column_formats to match the order of columns given in $data.
		$data_keys      = array_keys( $data );
		$column_formats = array_merge( array_flip( $data_keys ), $column_formats );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $wpdb->update( $this->table_name, $data, [ $where => $row_id ], $column_formats ) === false ) {
			return false;
		}

		do_action( 'wpforms_post_update_' . $type, $data );

		return true;
	}

	/**
	 * Delete a record from the database.
	 *
	 * @since 1.1.6
	 *
	 * @param int|string $row_id Row ID.
	 *
	 * @return bool False if the record could not be deleted, true otherwise.
	 */
	public function delete( $row_id = 0 ) {

		global $wpdb;

		// Row ID must be positive integer.
		$row_id = absint( $row_id );

		if ( empty( $row_id ) ) {
			return false;
		}

		do_action( 'wpforms_pre_delete', $row_id );
		do_action( 'wpforms_pre_delete_' . $this->type, $row_id );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( $wpdb->query( $wpdb->prepare( "DELETE FROM $this->table_name WHERE $this->primary_key = %d", $row_id ) ) === false ) {
			return false;
		}

		do_action( 'wpforms_post_delete', $row_id );
		do_action( 'wpforms_post_delete_' . $this->type, $row_id );

		return true;
	}

	/**
	 * Delete a record from the database by column.
	 *
	 * @since 1.1.6
	 *
	 * @param string     $column       Column name.
	 * @param int|string $column_value Column value.
	 *
	 * @return bool False if the record could not be deleted, true otherwise.
	 */
	public function delete_by( $column, $column_value ) {

		global $wpdb;

		if (
			empty( $column ) ||
			empty( $column_value ) ||
			! array_key_exists( $column, $this->get_columns() )
		) {
			return false;
		}

		do_action( 'wpforms_pre_delete', $column_value );
		do_action( 'wpforms_pre_delete_' . $this->type, $column_value );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( $wpdb->query( $wpdb->prepare( "DELETE FROM $this->table_name WHERE $column = %s", $column_value ) ) === false ) {
			return false;
		}

		do_action( 'wpforms_post_delete', $column_value );
		do_action( 'wpforms_post_delete_' . $this->type, $column_value );

		return true;
	}

	/**
	 * Delete record(s) from the database using WHERE IN syntax.
	 *
	 * @since 1.6.4
	 *
	 * @param string $column        Column name.
	 * @param mixed  $column_values Column values.
	 *
	 * @return int|bool Number of deleted records, false otherwise.
	 */
	public function delete_where_in( $column, $column_values ) {

		global $wpdb;

		if ( empty( $column ) || empty( $column_values ) ) {
			return false;
		}

		if ( ! array_key_exists( $column, $this->get_columns() ) ) {
			return false;
		}

		$values = is_array( $column_values ) ? $column_values : [ $column_values ];

		foreach ( $values as $key => $value ) {
			// Check if a string contains an integer and sanitize accordingly.
			if ( (string) (int) $value === $value ) {
				$values[ $key ]       = (int) $value;
				$placeholders[ $key ] = '%d';
			} else {
				$values[ $key ]       = sanitize_text_field( $value );
				$placeholders[ $key ] = '%s';
			}
		}

		$placeholders = isset( $placeholders ) ? implode( ',', $placeholders ) : '';
		$sql          = "DELETE FROM $this->table_name WHERE $column IN ( $placeholders )";

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->query( $wpdb->prepare( $sql, $values ) );
	}

	/**
	 * Check if the given table exists.
	 *
	 * @since 1.1.6
	 * @since 1.5.9 Default value is now the current child class table name.
	 *
	 * @param string $table The table name. Defaults to the child class table name.
	 *
	 * @return bool If the table name exists.
	 */
	public function table_exists( $table = '' ) {

		global $wpdb;

		if ( ! empty( $table ) ) {
			$table = sanitize_text_field( $table );
		} else {
			$table = $this->table_name;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	/**
	 * Build WHERE for a query.
	 *
	 * @since 1.7.2.2
	 *
	 * @param array           $args    Optional args.
	 * @param array           $keys    Allowed arg items.
	 * @param string|string[] $formats Formats of arg items.
	 *
	 * @return string
	 */
	protected function build_where( $args, $keys = [], $formats = [] ) {

		$formats = array_pad( $formats, count( $keys ), '%d' );
		$where   = '';

		foreach ( $keys as $index => $key ) {
			// Value `$args[ $key ]` can be a natural number and a numeric string.
			// We should skip empty string values, but continue working with '0'.
			if ( empty( $args[ $key ] ) && $args[ $key ] !== '0' ) {
				continue;
			}

			$ids = wpforms_wpdb_prepare_in( $args[ $key ], $formats[ $index ] );

			$where .= empty( $where ) ? 'WHERE' : 'AND';
			$where .= " `{$key}` IN ( {$ids} ) ";
		}

		return $where;
	}
}
