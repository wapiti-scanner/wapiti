<?php
/**
 * Table Checksums Class.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Replicastore;

use Automattic\Jetpack\Sync;
use Exception;
use WP_Error;

// TODO add rest endpoints to work with this, hopefully in the same folder.
/**
 * Class to handle Table Checksums.
 */
class Table_Checksum {

	/**
	 * Table to be checksummed.
	 *
	 * @var string
	 */
	public $table = '';

	/**
	 * Table Checksum Configuration.
	 *
	 * @var array
	 */
	public $table_configuration = array();

	/**
	 * Perform Text Conversion to latin1.
	 *
	 * @var boolean
	 */
	protected $perform_text_conversion = false;

	/**
	 * Field to be used for range queries.
	 *
	 * @var string
	 */
	public $range_field = '';

	/**
	 * ID Field(s) to be used.
	 *
	 * @var array
	 */
	public $key_fields = array();

	/**
	 * Field(s) to be used in generating the checksum value.
	 *
	 * @var array
	 */
	public $checksum_fields = array();

	/**
	 * Field(s) to be used in generating the checksum value that need latin1 conversion.
	 *
	 * @var array
	 */
	public $checksum_text_fields = array();

	/**
	 * Default filter values for the table
	 *
	 * @var array
	 */
	public $filter_values = array();

	/**
	 * SQL Query to be used to filter results (allow/disallow).
	 *
	 * @var string
	 */
	public $additional_filter_sql = '';

	/**
	 * Default Checksum Table Configurations.
	 *
	 * @var array
	 */
	public $default_tables = array();

	/**
	 * Salt to be used when generating checksum.
	 *
	 * @var string
	 */
	public $salt = '';

	/**
	 * Tables which are allowed to be checksummed.
	 *
	 * @var string
	 */
	public $allowed_tables = array();

	/**
	 * If the table has a "parent" table that it's related to.
	 *
	 * @var mixed|null
	 */
	protected $parent_table = null;

	/**
	 * What field to use for the parent table join, if it has a "parent" table.
	 *
	 * @var mixed|null
	 */
	protected $parent_join_field = null;

	/**
	 * What field to use for the table join, if it has a "parent" table.
	 *
	 * @var mixed|null
	 */
	protected $table_join_field = null;

	/**
	 * Some tables might not exist on the remote, and we want to verify they exist, before trying to query them.
	 *
	 * @var callable
	 */
	protected $is_table_enabled_callback = false;

	/**
	 * Table_Checksum constructor.
	 *
	 * @param string  $table The table to calculate checksums for.
	 * @param string  $salt  Optional salt to add to the checksum.
	 * @param boolean $perform_text_conversion If text fields should be latin1 converted.
	 *
	 * @throws Exception Throws exception from inner functions.
	 */
	public function __construct( $table, $salt = null, $perform_text_conversion = false ) {

		if ( ! Sync\Settings::is_checksum_enabled() ) {
			throw new Exception( 'Checksums are currently disabled.' );
		}

		$this->salt = $salt;

		$this->default_tables = $this->get_default_tables();

		$this->perform_text_conversion = $perform_text_conversion;

		// TODO change filters to allow the array format.
		// TODO add get_fields or similar method to get things out of the table.
		// TODO extract this configuration in a better way, still make it work with `$wpdb` names.
		// TODO take over the replicastore functions and move them over to this class.
		// TODO make the API work.

		$this->allowed_tables = apply_filters( 'jetpack_sync_checksum_allowed_tables', $this->default_tables );

		$this->table               = $this->validate_table_name( $table );
		$this->table_configuration = $this->allowed_tables[ $table ];

		$this->prepare_fields( $this->table_configuration );

		// Run any callbacks to check if a table is enabled or not.
		if (
			is_callable( $this->is_table_enabled_callback )
			&& ! call_user_func( $this->is_table_enabled_callback, $table )
		) {
			throw new Exception( "Unable to use table name: $table" );
		}
	}

	/**
	 * Get Default Table configurations.
	 *
	 * @return array
	 */
	protected function get_default_tables() {
		global $wpdb;

		return array(
			'posts'                      => array(
				'table'                     => $wpdb->posts,
				'range_field'               => 'ID',
				'key_fields'                => array( 'ID' ),
				'checksum_fields'           => array( 'post_modified_gmt' ),
				'filter_values'             => Sync\Settings::get_disallowed_post_types_structured(),
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'posts' );
				},
			),
			'postmeta'                   => array(
				'table'                     => $wpdb->postmeta,
				'range_field'               => 'post_id',
				'key_fields'                => array( 'post_id', 'meta_key' ),
				'checksum_text_fields'      => array( 'meta_key', 'meta_value' ),
				'filter_values'             => Sync\Settings::get_allowed_post_meta_structured(),
				'parent_table'              => 'posts',
				'parent_join_field'         => 'ID',
				'table_join_field'          => 'post_id',
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'posts' );
				},
			),
			'comments'                   => array(
				'table'                     => $wpdb->comments,
				'range_field'               => 'comment_ID',
				'key_fields'                => array( 'comment_ID' ),
				'checksum_fields'           => array( 'comment_date_gmt' ),
				'filter_values'             => array(
					'comment_type'     => array(
						'operator' => 'IN',
						'values'   => apply_filters(
							'jetpack_sync_whitelisted_comment_types',
							array( '', 'comment', 'trackback', 'pingback', 'review' )
						),
					),
					'comment_approved' => array(
						'operator' => 'NOT IN',
						'values'   => array( 'spam' ),
					),
				),
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'comments' );
				},
			),
			'commentmeta'                => array(
				'table'                     => $wpdb->commentmeta,
				'range_field'               => 'comment_id',
				'key_fields'                => array( 'comment_id', 'meta_key' ),
				'checksum_text_fields'      => array( 'meta_key', 'meta_value' ),
				'filter_values'             => Sync\Settings::get_allowed_comment_meta_structured(),
				'parent_table'              => 'comments',
				'parent_join_field'         => 'comment_ID',
				'table_join_field'          => 'comment_id',
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'comments' );
				},
			),
			'terms'                      => array(
				'table'                     => $wpdb->terms,
				'range_field'               => 'term_id',
				'key_fields'                => array( 'term_id' ),
				'checksum_fields'           => array( 'term_id' ),
				'checksum_text_fields'      => array( 'name', 'slug' ),
				'parent_table'              => 'term_taxonomy',
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'terms' );
				},
			),
			'termmeta'                   => array(
				'table'                     => $wpdb->termmeta,
				'range_field'               => 'term_id',
				'key_fields'                => array( 'term_id', 'meta_key' ),
				'checksum_text_fields'      => array( 'meta_key', 'meta_value' ),
				'parent_table'              => 'term_taxonomy',
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'terms' );
				},
			),
			'term_relationships'         => array(
				'table'                     => $wpdb->term_relationships,
				'range_field'               => 'object_id',
				'key_fields'                => array( 'object_id' ),
				'checksum_fields'           => array( 'object_id', 'term_taxonomy_id' ),
				'parent_table'              => 'term_taxonomy',
				'parent_join_field'         => 'term_taxonomy_id',
				'table_join_field'          => 'term_taxonomy_id',
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'terms' );
				},
			),
			'term_taxonomy'              => array(
				'table'                     => $wpdb->term_taxonomy,
				'range_field'               => 'term_taxonomy_id',
				'key_fields'                => array( 'term_taxonomy_id' ),
				'checksum_fields'           => array( 'term_taxonomy_id', 'term_id', 'parent' ),
				'checksum_text_fields'      => array( 'taxonomy', 'description' ),
				'filter_values'             => Sync\Settings::get_allowed_taxonomies_structured(),
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'terms' );
				},
			),
			'links'                      => $wpdb->links, // TODO describe in the array format or add exceptions.
			'options'                    => $wpdb->options, // TODO describe in the array format or add exceptions.
			'woocommerce_order_items'    => array(
				'table'                     => "{$wpdb->prefix}woocommerce_order_items",
				'range_field'               => 'order_item_id',
				'key_fields'                => array( 'order_item_id' ),
				'checksum_fields'           => array( 'order_id' ),
				'checksum_text_fields'      => array( 'order_item_name', 'order_item_type' ),
				'is_table_enabled_callback' => array( $this, 'enable_woocommerce_tables' ),
			),
			'woocommerce_order_itemmeta' => array(
				'table'                     => "{$wpdb->prefix}woocommerce_order_itemmeta",
				'range_field'               => 'order_item_id',
				'key_fields'                => array( 'order_item_id', 'meta_key' ),
				'checksum_text_fields'      => array( 'meta_key', 'meta_value' ),
				'filter_values'             => Sync\Settings::get_allowed_order_itemmeta_structured(),
				'parent_table'              => 'woocommerce_order_items',
				'parent_join_field'         => 'order_item_id',
				'table_join_field'          => 'order_item_id',
				'is_table_enabled_callback' => array( $this, 'enable_woocommerce_tables' ),
			),
			'users'                      => array(
				'table'                     => $wpdb->users,
				'range_field'               => 'ID',
				'key_fields'                => array( 'ID' ),
				'checksum_text_fields'      => array( 'user_login', 'user_nicename', 'user_email', 'user_url', 'user_registered', 'user_status', 'display_name' ),
				'filter_values'             => array(),
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'users' );
				},
			),

			/**
			 * Usermeta is a special table, as it needs to use a custom override flow,
			 * as the user roles, capabilities, locale, mime types can be filtered by plugins.
			 * This prevents us from doing a direct comparison in the database.
			 */
			'usermeta'                   => array(
				'table'                     => $wpdb->users,
				/**
				 * Range field points to ID, which in this case is the `WP_User` ID,
				 * since we're querying the whole WP_User objects, instead of meta entries in the DB.
				 */
				'range_field'               => 'ID',
				'key_fields'                => array(),
				'checksum_fields'           => array(),
				'is_table_enabled_callback' => function () {
					return false !== Sync\Modules::get_module( 'users' );
				},
			),
		);
	}

	/**
	 * Prepare field params based off provided configuration.
	 *
	 * @param array $table_configuration The table configuration array.
	 */
	protected function prepare_fields( $table_configuration ) {
		$this->key_fields                = $table_configuration['key_fields'];
		$this->range_field               = $table_configuration['range_field'];
		$this->checksum_fields           = isset( $table_configuration['checksum_fields'] ) ? $table_configuration['checksum_fields'] : array();
		$this->checksum_text_fields      = isset( $table_configuration['checksum_text_fields'] ) ? $table_configuration['checksum_text_fields'] : array();
		$this->filter_values             = isset( $table_configuration['filter_values'] ) ? $table_configuration['filter_values'] : null;
		$this->additional_filter_sql     = ! empty( $table_configuration['filter_sql'] ) ? $table_configuration['filter_sql'] : '';
		$this->parent_table              = isset( $table_configuration['parent_table'] ) ? $table_configuration['parent_table'] : null;
		$this->parent_join_field         = isset( $table_configuration['parent_join_field'] ) ? $table_configuration['parent_join_field'] : $table_configuration['range_field'];
		$this->table_join_field          = isset( $table_configuration['table_join_field'] ) ? $table_configuration['table_join_field'] : $table_configuration['range_field'];
		$this->is_table_enabled_callback = isset( $table_configuration['is_table_enabled_callback'] ) ? $table_configuration['is_table_enabled_callback'] : false;
	}

	/**
	 * Verify provided table name is valid for checksum processing.
	 *
	 * @param string $table Table name to validate.
	 *
	 * @return mixed|string
	 * @throws Exception Throw an exception on validation failure.
	 */
	protected function validate_table_name( $table ) {
		if ( empty( $table ) ) {
			throw new Exception( 'Invalid table name: empty' );
		}

		if ( ! array_key_exists( $table, $this->allowed_tables ) ) {
			throw new Exception( "Invalid table name: $table not allowed" );
		}

		return $this->allowed_tables[ $table ]['table'];
	}

	/**
	 * Verify provided fields are proper names.
	 *
	 * @param array $fields Array of field names to validate.
	 *
	 * @throws Exception Throw an exception on failure to validate.
	 */
	protected function validate_fields( $fields ) {
		foreach ( $fields as $field ) {
			if ( ! preg_match( '/^[0-9,a-z,A-Z$_]+$/i', $field ) ) {
				throw new Exception( "Invalid field name: $field is not allowed" );
			}

			// TODO other verifications of the field names.
		}
	}

	/**
	 * Verify the fields exist in the table.
	 *
	 * @param array $fields Array of fields to validate.
	 *
	 * @return bool
	 * @throws Exception Throw an exception on failure to validate.
	 */
	protected function validate_fields_against_table( $fields ) {
		global $wpdb;

		$valid_fields = array();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$result = $wpdb->get_results( "SHOW COLUMNS FROM {$this->table}", ARRAY_A );

		foreach ( $result as $result_row ) {
			$valid_fields[] = $result_row['Field'];
		}

		// Check if the fields are actually contained in the table.
		foreach ( $fields as $field_to_check ) {
			if ( ! in_array( $field_to_check, $valid_fields, true ) ) {
				throw new Exception( "Invalid field name: field '{$field_to_check}' doesn't exist in table {$this->table}" );
			}
		}

		return true;
	}

	/**
	 * Verify the configured fields.
	 *
	 * @throws Exception Throw an exception on failure to validate in the internal functions.
	 */
	protected function validate_input() {
		$fields = array_merge( array( $this->range_field ), $this->key_fields, $this->checksum_fields, $this->checksum_text_fields );

		$this->validate_fields( $fields );
		$this->validate_fields_against_table( $fields );
	}

	/**
	 * Prepare filter values as SQL statements to be added to the other filters.
	 *
	 * @param array  $filter_values The filter values array.
	 * @param string $table_prefix  If the values are going to be used in a sub-query, add a prefix with the table alias.
	 *
	 * @return array|null
	 */
	protected function prepare_filter_values_as_sql( $filter_values = array(), $table_prefix = '' ) {
		global $wpdb;

		if ( ! is_array( $filter_values ) ) {
			return null;
		}

		$result = array();

		foreach ( $filter_values as $field => $filter ) {
			$key = ( ! empty( $table_prefix ) ? $table_prefix : $this->table ) . '.' . $field;

			switch ( $filter['operator'] ) {
				case 'IN':
				case 'NOT IN':
					$values_placeholders = implode( ',', array_fill( 0, count( $filter['values'] ), '%s' ) );
					$statement           = "{$key} {$filter['operator']} ( $values_placeholders )";

					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
					$prepared_statement = $wpdb->prepare( $statement, $filter['values'] );

					$result[] = $prepared_statement;
					break;
			}
		}

		return $result;
	}

	/**
	 * Build the filter query baased off range fields and values and the additional sql.
	 *
	 * @param int|null   $range_from    Start of the range.
	 * @param int|null   $range_to      End of the range.
	 * @param array|null $filter_values Additional filter values. Not used at the moment.
	 * @param string     $table_prefix  Table name to be prefixed to the columns. Used in sub-queries where columns can clash.
	 *
	 * @return string
	 */
	public function build_filter_statement( $range_from = null, $range_to = null, $filter_values = null, $table_prefix = '' ) {
		global $wpdb;

		// If there is a field prefix that we want to use with table aliases.
		$parent_prefix = ( ! empty( $table_prefix ) ? $table_prefix : $this->table ) . '.';

		/**
		 * Prepare the ranges.
		 */

		$filter_array = array( '1 = 1' );
		if ( null !== $range_from ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$filter_array[] = $wpdb->prepare( "{$parent_prefix}{$this->range_field} >= %d", array( intval( $range_from ) ) );
		}
		if ( null !== $range_to ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$filter_array[] = $wpdb->prepare( "{$parent_prefix}{$this->range_field} <= %d", array( intval( $range_to ) ) );
		}

		/**
		 * End prepare the ranges.
		 */

		/**
		 * Prepare data filters.
		 */

		// Default filters.
		if ( $this->filter_values ) {
			$prepared_values_statements = $this->prepare_filter_values_as_sql( $this->filter_values, $table_prefix );
			if ( $prepared_values_statements ) {
				$filter_array = array_merge( $filter_array, $prepared_values_statements );
			}
		}

		// Additional filters.
		if ( ! empty( $filter_values ) ) {
			// Prepare filtering.
			$prepared_values_statements = $this->prepare_filter_values_as_sql( $filter_values, $table_prefix );
			if ( $prepared_values_statements ) {
				$filter_array = array_merge( $filter_array, $prepared_values_statements );
			}
		}

		// Add any additional filters via direct SQL statement.
		// Currently used only because we haven't converted all filtering to happen via `filter_values`.
		// This SQL is NOT prefixed and column clashes can occur when used in sub-queries.
		if ( $this->additional_filter_sql ) {
			$filter_array[] = $this->additional_filter_sql;
		}

		/**
		 * End prepare data filters.
		 */
		return implode( ' AND ', $filter_array );
	}

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

		$join_statement = '';
		if ( $this->parent_table ) {
			$parent_table_obj    = new Table_Checksum( $this->parent_table );
			$parent_filter_query = $parent_table_obj->build_filter_statement( null, null, null, 'parent_table' );

			// It is possible to have the GROUP By cause multiple rows to be returned for the same row for term_taxonomy.
			// To get distinct entries we use a correlatd subquery back on the parent table using the primary key.
			$additional_unique_clause = '';
			if ( 'term_taxonomy' === $this->parent_table ) {
				$additional_unique_clause = "
				AND parent_table.{$parent_table_obj->range_field} = (
				SELECT min( parent_table_cs.{$parent_table_obj->range_field} )
			            FROM {$parent_table_obj->table} as parent_table_cs
			            WHERE parent_table_cs.{$this->parent_join_field} = {$this->table}.{$this->table_join_field}
			        )
				";
			}

			$join_statement = "
			    INNER JOIN {$parent_table_obj->table} as parent_table
			    ON (
			        {$this->table}.{$this->table_join_field} = parent_table.{$this->parent_join_field}
			        AND {$parent_filter_query}
			        $additional_unique_clause
			    )
			";
		}

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

		// Performance :: When getting the postmeta range we do not want to filter by the whitelist.
		// The reason for this is that it leads to a non-performant query that can timeout.
		// Instead lets get the range based on posts regardless of meta.
		$filter_values = $this->filter_values;
		if ( 'postmeta' === $this->table ) {
			$this->filter_values = null;
		}

		// `trim()` to make sure we don't add the statement if it's empty.
		$filters = trim( $this->build_filter_statement( $range_from, $range_to ) );

		// Reset Post meta filter.
		if ( 'postmeta' === $this->table ) {
			$this->filter_values = $filter_values;
		}

		$filter_statement = '';
		if ( ! empty( $filters ) ) {
			$filter_statement = "
				WHERE
					{$filters}
			";
		}

		// Only make the distinct count when we know there can be multiple entries for the range column.
		$distinct_count = '';
		if ( count( $this->key_fields ) > 1 || $wpdb->terms === $this->table || $wpdb->term_relationships === $this->table ) {
			$distinct_count = 'DISTINCT';
		}

		$query = "
			SELECT
			       MIN({$this->range_field}) as min_range,
			       MAX({$this->range_field}) as max_range,
			       COUNT( {$distinct_count} {$this->range_field}) as item_count
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
						{$distinct_count} {$this->range_field}
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

	/**
	 * Update the results to have key/checksum format.
	 *
	 * @param array $results Prepare the results for output of granular results.
	 */
	protected function prepare_results_for_output( &$results ) {
		// get the compound key.
		// only return range and compound key for granular results.

		$return_value = array();

		foreach ( $results as &$result ) {
			// Working on reference to save memory here.

			$key = array();
			foreach ( $this->key_fields as $field ) {
				$key[] = $result[ $field ];
			}

			$return_value[ implode( '-', $key ) ] = $result['checksum'];
		}

		return $return_value;
	}

	/**
	 * Calculate the checksum based on provided range and filters.
	 *
	 * @param int|null   $range_from          The start of the range.
	 * @param int|null   $range_to            The end of the range.
	 * @param array|null $filter_values       Additional filter values. Not used at the moment.
	 * @param bool       $granular_result     If the returned result should be granular or only the checksum.
	 * @param bool       $simple_return_value If we want to use a simple return value for non-granular results (return only the checksum, without wrappers).
	 *
	 * @return array|mixed|object|WP_Error|null
	 */
	public function calculate_checksum( $range_from = null, $range_to = null, $filter_values = null, $granular_result = false, $simple_return_value = true ) {

		if ( ! Sync\Settings::is_checksum_enabled() ) {
			return new WP_Error( 'checksum_disabled', 'Checksums are currently disabled.' );
		}

		try {
			$this->validate_input();
		} catch ( Exception $ex ) {
			return new WP_Error( 'invalid_input', $ex->getMessage() );
		}

		$query = $this->build_checksum_query( $range_from, $range_to, $filter_values, $granular_result );

		global $wpdb;

		if ( ! $granular_result ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$result = $wpdb->get_row( $query, ARRAY_A );

			if ( ! is_array( $result ) ) {
				return new WP_Error( 'invalid_query', "Result wasn't an array" );
			}

			if ( $simple_return_value ) {
				return $result['checksum'];
			}

			return array(
				'range'    => $range_from . '-' . $range_to,
				'checksum' => $result['checksum'],
			);
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$result = $wpdb->get_results( $query, ARRAY_A );
			return $this->prepare_results_for_output( $result );
		}
	}

	/**
	 * Make sure the WooCommerce tables should be enabled for Checksum/Fix.
	 *
	 * @return bool
	 */
	protected function enable_woocommerce_tables() {
		/**
		 * On WordPress.com, we can't directly check if the site has support for WooCommerce.
		 * Having the option to override the functionality here helps with syncing WooCommerce tables.
		 *
		 * @since 10.1
		 *
		 * @param bool If we should we force-enable WooCommerce tables support.
		 */
		$force_woocommerce_support = apply_filters( 'jetpack_table_checksum_force_enable_woocommerce', false );

		// If we're forcing WooCommerce tables support, there's no need to check further.
		// This is used on WordPress.com.
		if ( $force_woocommerce_support ) {
			return true;
		}

		// No need to proceed if WooCommerce is not available.
		if ( ! class_exists( 'WooCommerce' ) ) {
			return false;
		}

		// TODO more checks if needed. Probably query the DB to make sure the tables exist.

		return true;
	}

}
