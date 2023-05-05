<?php
namespace W3TC;

/**
 * class DbCache_WpdbInjection
 * Allows to perform own operation instead of default behaviour of wpdb
 * without inheritance
 */
class DbCache_WpdbInjection {
	/**
	 * Top database-connection object.
	 * Initialized by DbCache_Wpdb::instance
	 *
	 * @var object
	 */
	protected $wpdb_mixin = null;

	/**
	 * Database-connection using overrides of next processor in queue
	 * Initialized by DbCache_Wpdb::instance
	 *
	 * @var object
	 */
	protected $next_injection = null;

	/**
	 * initialization of object so that it can be used
	 */
	function initialize_injection( $wpdb_mixin, $next_injection ) {
		$this->wpdb_mixin = $wpdb_mixin;
		$this->next_injection = $next_injection;
	}

	/**
	 * Placeholder for database initialization
	 */
	function initialize() {
		return $this->wpdb_mixin->default_initialize();
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function insert( $table, $data, $format = null ) {
		return $this->wpdb_mixin->default_insert( $table, $data, $format );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function query( $query ) {
		return $this->wpdb_mixin->default_query( $query );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function _escape( $data ) {
		return $this->wpdb_mixin->default__escape( $data );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function prepare( $query, $args ) {
		return $this->wpdb_mixin->default_prepare( $query, $args );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function replace( $table, $data, $format = null ) {
		return $this->wpdb_mixin->default_replace( $table, $data, $format );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function update( $table, $data, $where, $format = null, $where_format = null ) {
		return $this->wpdb_mixin->default_update( $table, $data, $where, $format, $where_format );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function delete( $table, $where, $where_format = null ) {
		return $this->wpdb_mixin->default_delete( $table, $where, $where_format );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function init_charset() {
		return $this->wpdb_mixin->default_init_charset();
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function set_charset( $dbh, $charset = null, $collate = null ) {
		return $this->wpdb_mixin->default_set_charset( $dbh, $charset, $collate );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function set_sql_mode( $modes = array() ) {
		return $this->wpdb_mixin->default_set_sql_mode( $modes );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function flush() {
		return $this->wpdb_mixin->default_flush();
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function check_database_version( $dbh_or_table = false ) {
		return $this->wpdb_mixin->default_check_database_version( $dbh_or_table );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function supports_collation( $dbh_or_table = false ) {
		return $this->wpdb_mixin->default_supports_collation( $dbh_or_table );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function has_cap( $db_cap, $dbh_or_table = false ) {
		return $this->wpdb_mixin->default_has_cap( $db_cap, $dbh_or_table );
	}

	/**
	 * Placeholder for apropriate wp_db method replacement.
	 * By default calls wp_db implementation
	 */
	function db_version( $dbh_or_table = false ) {
		return $this->wpdb_mixin->default_db_version( $dbh_or_table );
	}

	public function w3tc_footer_comment( $strings ) {
		return $strings;
	}

	public function w3tc_usage_statistics_of_request( $storage ) {
	}

	public function flush_cache( $extras = array() ) {
		return true;
	}
}
