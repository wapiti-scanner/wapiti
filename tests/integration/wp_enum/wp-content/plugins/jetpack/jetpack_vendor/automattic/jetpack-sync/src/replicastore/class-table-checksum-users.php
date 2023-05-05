<?php
/**
 * Table Checksums Class.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Replicastore;

/**
 * Class to handle Table Checksums for the Users table.
 */
class Table_Checksum_Users extends Table_Checksum {

	/**
	 * Returns the checksum query. All validation of fields and configurations are expected to occur prior to usage.
	 *
	 * @param int|null   $range_from      The start of the range.
	 * @param int|null   $range_to        The end of the range.
	 * @param array|null $filter_values   Additional filter values. Not used at the moment.
	 * @param bool       $granular_result If the function should return a granular result.
	 *
	 * @return string
	 *
	 * @throws Exception Throws an exception if validation fails in the internal function calls.
	 */
	protected function build_checksum_query( $range_from = null, $range_to = null, $filter_values = null, $granular_result = false ) {
		global $wpdb;

		// Escape the salt.
		$salt = $wpdb->prepare( '%s', $this->salt );

		// Prepare the compound key.
		$key_fields = array();

		// Prefix the fields with the table name, to avoid clashes in queries with sub-queries (e.g. meta tables).
		foreach ( $this->key_fields as $field ) {
			$key_fields[] = $this->table . '.' . $field;
		}

		$key_fields = implode( ',', $key_fields );

		// Prepare the checksum fields.
		$checksum_fields = array();
		// Prefix the fields with the table name, to avoid clashes in queries with sub-queries (e.g. meta tables).
		foreach ( $this->checksum_fields as $field ) {
			$checksum_fields[] = $this->table . '.' . $field;
		}
		// Apply latin1 conversion if enabled.
		if ( $this->perform_text_conversion ) {
			// Convert text fields to allow for encoding discrepancies as WP.com is latin1.
			foreach ( $this->checksum_text_fields as $field ) {
				$checksum_fields[] = 'CONVERT(' . $this->table . '.' . $field . ' using latin1 )';
			}
		} else {
			// Conversion disabled, default to table prefixing.
			foreach ( $this->checksum_text_fields as $field ) {
				$checksum_fields[] = $this->table . '.' . $field;
			}
		}

		$checksum_fields_string = implode( ',', array_merge( $checksum_fields, array( $salt ) ) );

		$additional_fields = '';
		if ( $granular_result ) {
			// TODO uniq the fields as sometimes(most) range_index is the key and there's no need to select the same field twice.
			$additional_fields = "
				{$this->table}.{$this->range_field} as range_index,
			    {$key_fields},
			";
		}

		$filter_stamenet = $this->build_filter_statement( $range_from, $range_to, $filter_values );

		// usermeta join to limit on user_level.
		$join_statement = "JOIN {$wpdb->usermeta} as um_table ON um_table.user_id = {$this->table}.ID";

		$query = "
			SELECT
				{$additional_fields}
				SUM(
					CRC32(
						CONCAT_WS( '#', {$salt}, {$checksum_fields_string} )
					)
				)  AS checksum
			 FROM
			    {$this->table}
				{$join_statement}
			 WHERE
				{$filter_stamenet}
				AND um_table.meta_key = '{$wpdb->prefix}user_level'
			  	AND um_table.meta_value > 0
		";

		/**
		 * We need the GROUP BY only for compound keys.
		 */
		if ( $granular_result ) {
			$query .= "
				GROUP BY {$key_fields}
				LIMIT 9999999
			";
		}

		return $query;
	}

	/**
	 * Obtain the min-max values (edges) of the range.
	 *
	 * @param int|null $range_from The start of the range.
	 * @param int|null $range_to   The end of the range.
	 * @param int|null $limit      How many values to return.
	 *
	 * @return array|object|void
	 * @throws Exception Throws an exception if validation fails on the internal function calls.
	 */
	public function get_range_edges( $range_from = null, $range_to = null, $limit = null ) {
		global $wpdb;

		$this->validate_fields( array( $this->range_field ) );

		// `trim()` to make sure we don't add the statement if it's empty.
		$filters = trim( $this->build_filter_statement( $range_from, $range_to ) );

		$filter_statement = '';
		if ( ! empty( $filters ) ) {
			$filter_statement = "
				JOIN {$wpdb->usermeta} as um_table ON um_table.user_id = {$this->table}.ID
				WHERE
					{$filters}
					AND um_table.meta_key = '{$wpdb->prefix}user_level'
			  	    AND um_table.meta_value > 0
			";
		}

		$query = "
			SELECT
			       MIN({$this->range_field}) as min_range,
			       MAX({$this->range_field}) as max_range,
			       COUNT( {$this->range_field} ) as item_count
			FROM
		";

		/**
		 * If `$limit` is not specified, we can directly use the table.
		 */
		if ( ! $limit ) {
			$query .= "
				{$this->table}
	            {$filter_statement}
			";
		} else {
			/**
			 * If there is `$limit` specified, we can't directly use `MIN/MAX()` as they don't work with `LIMIT`.
			 * That's why we will alter the query for this case.
			 */
			$limit = intval( $limit );

			$query .= "
				(
					SELECT
						{$this->range_field}
					FROM
						{$this->table}
						{$filter_statement}
					ORDER BY
						{$this->range_field} ASC
					LIMIT {$limit}
				) as ids_query
			";
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$result = $wpdb->get_row( $query, ARRAY_A );

		if ( ! $result || ! is_array( $result ) ) {
			throw new Exception( 'Unable to get range edges' );
		}

		return $result;
	}

}
