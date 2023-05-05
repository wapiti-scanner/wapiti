<?php
namespace W3TC;

/**
 * class Enterprise_Dbcache_WpdbInjection_Cluster
 * Support of database cluster
 */
class Enterprise_Dbcache_WpdbInjection_Cluster extends DbCache_WpdbInjection {
	/**
	 * Whether to check with fsockopen prior to mysqli_connect.
	 *
	 * @var bool
	 */
	public $check_tcp_responsiveness = true;

	/**
	 * Minimum number of connections to try before bailing
	 *
	 * @var int
	 */
	public $min_tries = 3;

	/**
	 * Whether to use mysqli_connect with persistence
	 *
	 * @var bool
	 */
	public $persistent = false;

	/**
	 * Cache of tables-to-dataset mapping if blog_dataset callback defined
	 *
	 * @var array
	 */
	private $_blog_to_dataset = array();

	/**
	 * Optional directory of callbacks to determine datasets from queries
	 *
	 * @var array
	 */
	private $_callbacks = array();

	/**
	 * The multi-dimensional array of datasets and servers
	 *
	 * @var array
	 */
	private $_cluster_servers = array();

	/**
	 * Zone where application runs
	 *
	 * @var array
	 */
	private $_current_zone = array( 'name' => 'all', 'zone_priorities' => array( 'all' ) );

	/**
	 * Established connections
	 *
	 * @var array
	 */
	private $_connections;

	/**
	 * After any SQL_CALC_FOUND_ROWS query, the query "SELECT FOUND_ROWS()"
	 * is sent and the mysql result resource stored here. The next query
	 * for FOUND_ROWS() will retrieve this. We do this to prevent any
	 * intervening queries from making FOUND_ROWS() inaccessible. You may
	 * prevent this by adding "NO_SELECT_FOUND_ROWS" in a comment.
	 *
	 * @var resource
	 */
	private $_last_found_rows_result;

	/**
	 * The last table that was queried
	 *
	 * @var string
	 */
	private $_last_table;

	/**
	 * Reject reason
	 */
	private $_reject_reason = null;

	/**
	 * Send Reads To Masters. This disables slave connections while true.
	 * Otherwise it is an array of written tables.
	 *
	 * @var array
	 */
	private $_send_reads_to_master = false;


	/**
	 * Send all request to master db if user is in administration.
	 *
	 * @var bool
	 */
	public $use_master_in_backend = true;

	/**
	 * Which charset to use for connections
	 *
	 * @var string
	 */
	public $charset = null;

	/**
	 * Which collate to use for connections
	 *
	 * @var string
	 */
	public $collate = null;

	/**
	 * Initializes object
	 */
	function initialize() {
		global $wpdb_cluster;
		$wpdb_cluster = $this;

		if ( !isset( $GLOBALS['w3tc_dbcluster_config'] ) && file_exists( WP_CONTENT_DIR . '/db-cluster-config.php' ) ) {
			// The config file resides in WP_CONTENT_DIR
			require WP_CONTENT_DIR . '/db-cluster-config.php';
		}

		if ( isset( $GLOBALS['w3tc_dbcluster_config'] ) ) {
			$this->apply_configuration( $GLOBALS['w3tc_dbcluster_config'] );
		} else {
			$this->_reject_reason = 'w3tc dbcluster configuration not found, ' .
				'using single-server configuration';
			$this->next_injection->initialize();
			return;
		}

		if ( WP_DEBUG )
			$this->wpdb_mixin->show_errors();

		$this->wpdb_mixin->dbh = null;
		$this->wpdb_mixin->ready = true;

		$this->init_charset();
	}


	/**
	 * Applies configuration from array
	 */
	public function apply_configuration( $c ) {
		if ( isset( $c['persistent'] ) ) {
			$this->persistent = $c['persistent'];
		}
		if ( isset( $c['check_tcp_responsiveness'] ) ) {
			$this->persistent = $c['check_tcp_responsiveness'];
		}
		if ( isset( $c['use_master_in_backend'] ) ) {
			$this->persistent = $c['use_master_in_backend'];
		}
		if ( isset( $c['charset'] ) ) {
			$this->persistent = $c['charset'];
		}
		if ( isset( $c['collate'] ) ) {
			$this->persistent = $c['collate'];
		}

		if ( isset( $c['filters'] ) && is_array( $c['filters'] ) ) {
			foreach ($c['filters'] as $filter) {
				$this->add_callback( $filter['function_to_add'], $filter['tag'] );
			}
		}

		if ( isset( $c['databases'] ) && is_array( $c['databases'] ) ) {
			foreach ($c['databases'] as $key => $db) {
				$this->add_database( $db );
			}
		}

		if ( isset( $c['zones'] ) && is_array( $c['zones'] ) ) {
			foreach ($c['zones'] as $key => $zone) {
				$zone['name'] = $key;
				$this->add_zone( $zone );
			}
		}
	}

	/**
	 * Sets default charset and collate
	 * If DB_CHARSET not set uses utf8
	 * If DB_COLLATE not set uses utf8_general_ci if multisite.
	 */
	function init_charset() {
		if ( function_exists( 'is_multisite' ) && is_multisite() ) {
			if ( defined( 'DB_COLLATE' ) && DB_COLLATE )
				$this->wpdb_mixin->collate = DB_COLLATE;
			else
				$this->wpdb_mixin->collate = 'utf8_general_ci';
		} elseif ( defined( 'DB_COLLATE' ) ) {
			$this->wpdb_mixin->collate = DB_COLLATE;
		}

		if ( defined( 'DB_CHARSET' ) )
			$this->wpdb_mixin->charset = DB_CHARSET;
		else
			$this->wpdb_mixin->charset = 'utf8';
	}

	/**
	 * Adds zone which defines priorities based on current application location
	 *
	 * @param array   $zone
	 *   keys:
	 *    name
	 *    SERVER_NAME
	 *    zone_priorities array
	 */
	function add_zone( $zone ) {
		if ( $this->_is_current_zone( $zone ) ) {
			if ( !isset( $zone['zone_priorities'] ) || !is_array( $zone['zone_priorities'] ) ) {
				die( 'zone_priorities key must be defined' );
			}

			$this->_current_zone = $zone;
			$this->_run_callbacks( 'current_zone_set', $zone );
		}
	}

	/**
	 * Add the connection parameters for a database
	 *
	 * @param array   $db
	 *   keys:
	 *     name
	 *     dataset
	 *     read
	 *     write
	 *     host
	 *     user
	 *     password
	 *     connect_function
	 *     timeout
	 *     zone
	 */
	function add_database( $db ) {
		$dataset = ( isset( $db['dataset'] ) ? $db['dataset'] : 'global' );
		unset( $db['dataset'] );

		$read = ( isset( $db['read'] ) ? $db['read'] : true );
		unset( $db['read'] );
		$write = ( isset( $db['write'] ) ? $db['write'] : true );
		unset( $db['write'] );

		$zone = ( isset( $db['zone'] ) ? $db['zone'] : 'all' );
		unset( $db['zone'] );

		if ( !isset( $db['timeout'] ) )
			$db['timeout'] = 0.2;
		if ( !isset( $db['name'] ) )
			$db['name'] = $db['host'];

		if ( $read )
			$this->_cluster_servers[$dataset]['read'][$zone][] = $db;
		if ( $write )
			$this->_cluster_servers[$dataset]['write'][$zone][] = $db;
	}

	/**
	 * Add a callback to a group of callbacks.
	 * The default group is 'dataset', used to examine
	 * queries and determine dataset.
	 *
	 * @param object  $callback
	 * @param string  $group
	 */
	function add_callback( $callback, $group = 'dataset' ) {
		$this->_callbacks[$group][] = $callback;
	}

	/**
	 * Set a flag to prevent reading from slaves which might be lagging after a write
	 */
	function send_reads_to_masters() {
		$this->_send_reads_to_master = true;
	}

	/**
	 * If requests should be send to master or not.
	 *
	 * @return bool
	 */
	function send_to_masters() {
		return is_admin() && $this->use_master_in_backend;
	}

	/**
	 * Figure out which database server should handle the query, and connect to it.
	 *
	 * @param string  $query
	 * @return resource mysql database connection
	 */
	function db_connect( $query = '', $use_master = null ) {
		if ( empty( $this->_cluster_servers ) )
			return $this->_db_connect_fallback();

		$this->wpdb_mixin->dbh = null;

		if ( empty( $query ) )
			return false;

		$this->_last_table = $this->wpdb_mixin->table = $this->_get_table_from_query( $query );

		$this->callback_result = $this->_run_callbacks( 'dataset', $query );
		if ( !is_null( $this->callback_result ) )
			$dataset = $this->callback_result;
		elseif ( isset( $this->_callbacks['blog_dataset'] ) ) {
			if ( preg_match( '/^' . $this->wpdb_mixin->base_prefix . '(\d+)_/i',
					$this->wpdb_mixin->table, $matches ) ) {
				$blog_id = $matches[1];

				if ( isset( $this->_blog_to_dataset[$blog_id] ) )
					$dataset = $this->_blog_to_dataset[$blog_id];
				else {
					$this->callback_result = $this->_run_callbacks( 'blog_dataset', $blog_id );
					if ( !is_null( $this->callback_result ) ) {
						$dataset = $this->callback_result;
						$this->_blog_to_dataset[$blog_id] = $dataset;
					}
				}
			}
		}

		$dataset = ( isset( $dataset ) ? $dataset : 'global' );
		$this->dataset = $dataset;

		// Determine whether the query must be sent to the master (a writable server)
		if ( is_null( $use_master ) ) {
			if ( $this->_send_reads_to_master || $this->send_to_masters() ) {
				$use_master = true;
			} elseif ( defined( 'DONOTBCLUSTER' ) && DONOTBCLUSTER ) {
				$use_master = true;
			} elseif ( $is_write = $this->_is_write_query( $query ) ) {
				$use_master = true;
			} else {
				$use_master = false;
			}
		}

		if ( $use_master ) {
			$this->dbhname = $dataset . '__w';
			$operation = 'write';
		} else {
			$this->dbhname = $dataset . '__r';
			$operation = 'read';
		}

		// Try to reuse an existing connection
		$dbh = $this->_db_connect_reuse_connection();
		if ( is_object( $dbh ) ) {
			$this->wpdb_mixin->dbh = $dbh;
			return $dbh;
		}

		if ( empty( $this->_cluster_servers[$dataset][$operation] ) )
			return $this->wpdb_mixin->bail( "No databases available for dataset $dataset operation $operation" );

		// Make a list of at least $this->min_tries connections to try, repeating as necessary.
		$servers = array();
		do {
			foreach ( $this->_current_zone['zone_priorities'] as $zone ) {
				if ( isset( $this->_cluster_servers[$dataset][$operation][$zone] ) ) {
					$zone_servers = $this->_cluster_servers[$dataset][$operation][$zone];

					if ( is_array( $zone_servers ) ) {
						$indexes = array_keys( $zone_servers );
						shuffle( $indexes );
						foreach ( $indexes as $index )
							$servers[] = compact( 'zone', 'index' );
					}
				}
			}
		} while ( count( $servers ) < $this->min_tries );
		// Connect to a database server
		$success = false;
		$errno = 0;
		$dbhname = $this->dbhname;

		foreach ( $servers as $zone_index ) {
			// $zone, $index
			extract( $zone_index, EXTR_OVERWRITE );

			// $host, $user, $password, $name, $read, $write, $timeout
			extract( $this->_cluster_servers[$dataset][$operation][$zone][$index], EXTR_OVERWRITE );

			// Split host:port into $host and $port
			list( $host, $port ) = Util_Content::endpoint_to_host_port( $host, 3306 );

			$this->wpdb_mixin->timer_start();

			// Connect if necessary or possible
			$tcp_responded = null;
			if ( $this->check_tcp_responsiveness ) {
				$tcp_responded = $this->_check_tcp_responsiveness( $host, $port, $timeout );
			}

			$dbh = null;
			if ( is_null( $tcp_responded ) || $tcp_responded ) {
				$dbh = mysqli_init();

				$socket = null;
				$client_flags = defined( 'MYSQL_CLIENT_FLAGS' ) ? MYSQL_CLIENT_FLAGS : 0;

				if ( WP_DEBUG ) {
					mysqli_real_connect( $dbh, $host, $user, $password, null, $port, $socket, $client_flags );
				} else {
					@mysqli_real_connect( $dbh, $host, $user, $password, null, $port, $socket, $client_flags );
				}
			}

			$elapsed = $this->wpdb_mixin->timer_stop();

			if ( !is_null( $dbh ) ) {
				if ( $dbh->connect_errno ) {
					$errno = $dbh->connect_errno;
				} elseif ( mysqli_select_db( $dbh, $name ) ) {
					$this->_connections[$dbhname] = array(
						'dbh' => $dbh,
						'database_name' => $name );
					$success = true;
					break;
				}
			}
		}

		if ( !$success ) {
			if ( !$use_master ) {
				return $this->db_connect( $query, true );
			}

			return $this->wpdb_mixin->bail( "Unable to connect to $host:$port to $operation table '{$this->wpdb_mixin->table}' ($dataset) with $errno" );
		}

		$dbh = $this->_connections[$dbhname]['dbh'];
		$this->wpdb_mixin->dbh = $dbh; // needed by $wpdb->_real_escape()
		$this->set_charset( $dbh, $this->charset, $this->collate );
		$this->set_sql_mode();

		return $dbh;
	}

	/*
	 * Checks if this is our zone
	 *
	 * @param $zone array
	 * @return boolean
	 */
	function _is_current_zone( $zone ) {
		$server_name = isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '';
		// obsolete.
		if ( isset( $zone['SERVER_NAME'] ) ) {
			if ( $server_name === $zone['SERVER_NAME'] ) {
				return true;
			}
		}

		if ( isset( $zone['server_names'] ) ) {
			if ( ! is_array( $zone['server_names'] ) ) {
				die( 'server_names must be defined as array' );
			}
			foreach ( $zone['server_names'] as $zone_server_name ) {
				if ( '*' === $zone_server_name ) {
					return true;
				}
				if ( $server_name === $zone_server_name ) {
					return true;
				}
			}
		}

		return false;
	}

	/*
	 * Tries to reuse opened connection
	 *
	 * @return resource
	 */
	function _db_connect_reuse_connection() {
		$dbhname = $this->dbhname;

		if ( !isset( $this->_connections[$dbhname] ) )
			return null;

		$connection = & $this->_connections[$dbhname];
		$dbh = $connection['dbh'];

		if ( !is_object( $dbh ) )
			return null;

		if ( !mysqli_ping( $dbh ) ) {
			// disconnect (ping failed)
			$this->_disconnect( $dbhname );
			return null;
		}

		return $dbh;
	}

	/**
	 * Sets the connection's character set.
	 *
	 * @param resource $dbh     The resource given by mysqli_connect
	 * @param string  $charset The character set (optional)
	 * @param string  $collate The collation (optional)
	 */
	function set_charset( $dbh, $charset = null, $collate = null ) {
		if ( !isset( $charset ) )
			$charset = $this->wpdb_mixin->charset;
		if ( !isset( $collate ) )
			$collate = $this->wpdb_mixin->collate;
		if ( $this->has_cap( 'collation', $dbh ) && !empty( $charset ) ) {
			if ( function_exists( 'mysqli_set_charset' ) && $this->has_cap( 'set_charset', $dbh ) ) {
				mysqli_set_charset( $dbh, $charset );
				$this->wpdb_mixin->real_escape = true;
			} else {
				$query = $this->wpdb_mixin->prepare( 'SET NAMES %s', $charset );
				if ( !empty( $collate ) )
					$query .= $this->wpdb_mixin->prepare( ' COLLATE %s', $collate );
				mysqli_query( $dbh, $query );
			}
		}
	}

	/**
	 * Kill cached query results
	 */
	function flush() {
		$this->wpdb_mixin->last_error = '';
		$this->num_rows = 0;
		$this->next_injection->flush();
	}

	/**
	 * Basic query. See docs for more details.
	 *
	 * @param string  $query
	 * @return int number of rows
	 */
	function query( $query ) {
		// some queries are made before the plugins have been loaded, and thus cannot be filtered with this method
		if ( function_exists( 'apply_filters' ) )
			$query = apply_filters( 'query', $query );

		$this->flush();

		// Log how the function was called
		$this->wpdb_mixin->func_call = "\$db->query(\"$query\")";

		// Keep track of the last query for debug..
		$this->wpdb_mixin->last_query = $query;

		if ( preg_match( '/^\s*SELECT\s+FOUND_ROWS(\s*)/i', $query )
			&& is_object( $this->wpdb_mixin->_last_found_rows_result ) ) {
			$this->wpdb_mixin->result = $this->wpdb_mixin->_last_found_rows_result;
			$elapsed = 0;
		} else {
			$this->db_connect( $query );
			if ( !is_object( $this->wpdb_mixin->dbh ) )
				return false;

			$this->wpdb_mixin->timer_start();
			$this->wpdb_mixin->result = mysqli_query( $this->wpdb_mixin->dbh, $query );
			$elapsed = $this->wpdb_mixin->timer_stop();
			++$this->wpdb_mixin->num_queries;

			if ( preg_match( '/^\s*SELECT\s+SQL_CALC_FOUND_ROWS\s/i', $query ) ) {
				if ( false === strpos( $query, "NO_SELECT_FOUND_ROWS" ) ) {
					$this->wpdb_mixin->timer_start();
					$this->wpdb_mixin->_last_found_rows_result = mysqli_query( $this->wpdb_mixin->dbh, "SELECT FOUND_ROWS()" );
					$elapsed += $this->wpdb_mixin->timer_stop();
					++$this->wpdb_mixin->num_queries;
					$query .= "; SELECT FOUND_ROWS()";
				}
			} else {
				$this->wpdb_mixin->_last_found_rows_result = null;
			}
		}

		if ( function_exists( 'apply_filters' ) )
			apply_filters( 'after_query', $query );

		// If there is an error then take note of it
		if ( $this->wpdb_mixin->last_error = mysqli_error( $this->wpdb_mixin->dbh ) ) {
			$this->wpdb_mixin->print_error( $this->wpdb_mixin->last_error );
			return false;
		}

		if ( preg_match( "/^\\s*(insert|delete|update|replace|alter) /i", $query ) ) {
			$this->wpdb_mixin->rows_affected = mysqli_affected_rows( $this->wpdb_mixin->dbh );

			// Take note of the insert_id
			if ( preg_match( "/^\\s*(insert|replace) /i", $query ) ) {
				$this->wpdb_mixin->insert_id = mysqli_insert_id( $this->wpdb_mixin->dbh );
			}
			// Return number of rows affected
			return $this->wpdb_mixin->rows_affected;
		} else {
			$i = 0;
			$this->wpdb_mixin->col_info = array();
			$col_info = array();
			while ( $i < @mysqli_num_fields( $this->wpdb_mixin->result ) ) {
				$col_info[$i] = @mysqli_fetch_field( $this->wpdb_mixin->result );
				$i++;
			}
			$this->wpdb_mixin->col_info = $col_info;
			$num_rows = 0;
			$this->wpdb_mixin->last_result = array();
			while ( $row = @mysqli_fetch_object( $this->wpdb_mixin->result ) ) {
				$this->wpdb_mixin->last_result[$num_rows] = $row;
				$num_rows++;
			}

			// Log number of rows the query returned
			$this->num_rows = $num_rows;

			// Return number of rows selected
			return $num_rows;
		}
	}

	/**
	 * Usually it's called from inside other higher-level function
	 * so connection is available, but sometimes called directly.
	 * So connection should be initialized
	 **/
	function _escape( $data ) {
		if ( !$this->wpdb_mixin->dbh ) {
			$this->db_connect( 'SELECT * FROM nothing' );
		}

		return $this->wpdb_mixin->default__escape( $data );
	}

	/**
	 * Prepare calls escape, so database connection required
	 **/
	function prepare( $query, $args ) {
		if ( !$this->wpdb_mixin->dbh ) {
			$this->db_connect( $query );
		}

		return $this->wpdb_mixin->default_prepare( $query, $args );
	}

	/**
	 * Whether or not MySQL database is at least the required minimum version.
	 * The additional argument allows the caller to check a specific database.
	 *
	 * @param string  $dbh_or_table
	 * @return WP_Error
	 */
	function check_database_version( $dbh_or_table = false ) {
		global $wp_version;
		// Make sure the server has MySQL 4.1.2
		$mysqli_version = preg_replace( '|[^0-9\.]|', '', $this->wpdb_mixin->db_version( $dbh_or_table ) );
		if ( version_compare( $mysqli_version, '4.1.2', '<' ) )
			return new \WP_Error( 'database_version', sprintf( __( '<strong>ERROR</strong>: WordPress %s requires MySQL 4.1.2 or higher' ), $wp_version ) );
	}

	/**
	 * This function is called when WordPress is generating the table schema to determine wether or not the current database
	 * supports or needs the collation statements.
	 * The additional argument allows the caller to check a specific database.
	 *
	 * @param string  $dbh_or_table
	 * @return bool
	 */
	function supports_collation( $dbh_or_table = false ) {
		return $this->wpdb_mixin->has_cap( 'collation', $dbh_or_table );
	}

	/**
	 * Generic function to determine if a database supports a particular feature
	 * The additional argument allows the caller to check a specific database.
	 *
	 * @param string  $db_cap       the feature
	 * @param bool|string|resource $dbh_or_table the databaese (the current database, the database housing the specified table, or the database of the mysql resource)
	 * @return bool
	 */
	function has_cap( $db_cap, $dbh_or_table = false ) {
		$version = $this->wpdb_mixin->db_version( $dbh_or_table );

		switch ( strtolower( $db_cap ) ) :
		case 'collation' :
		case 'group_concat' :
		case 'subqueries' :
			return version_compare( $version, '4.1', '>=' );
	case 'set_charset' :
		return version_compare( $version, '5.0.7', '>=' );
		endswitch;

		return false;
	}

	/**
	 * The database version number
	 *
	 * @param false|string|resource $dbh_or_table the databaese (the current database, the database housing the specified table, or the database of the mysql resource)
	 * @return false|string false on failure, version number on success
	 */
	function db_version( $dbh_or_table = false ) {
		$dbh = null;
		if ( !$dbh_or_table && $this->wpdb_mixin->dbh )
			$dbh = $this->wpdb_mixin->dbh;
		elseif ( is_object( $dbh_or_table ) )
			$dbh = $dbh_or_table;
		else
			$dbh = $this->db_connect( "SELECT FROM $dbh_or_table $this->wpdb_mixin->users" );

		if ( !is_null( $dbh ) )
			return preg_replace( '/[^0-9.].*/', '', mysqli_get_server_info( $dbh ) );
		return false;
	}

	/**
	 * Disconnect and remove connection from open connections list
	 *
	 * @param string  $dbhname
	 */
	function _disconnect( $dbhname ) {
		if ( isset( $this->_connections[$dbhname] ) ) {
			$dbh = $this->_connections[$dbhname]['dbh'];
			if ( is_object( $dbh ) )
				mysqli_close( $dbh );

			unset( $this->_connections[$dbhname] );
		}
	}

	/**
	 * Check the responsiveness of a tcp/ip daemon
	 *
	 * @return (bool) true when $host:$post responds within $float_timeout seconds, else (bool) false
	 */
	function _check_tcp_responsiveness( $host, $port, $float_timeout ) {
		$socket = @ fsockopen( $host, $port, $errno, $errstr, $float_timeout );
		if ( $socket === false )
			return "[ > $float_timeout ] ($errno) '$errstr'";
		fclose( $socket );
		return true;
	}

	/**
	 * Find the first table name referenced in a query
	 *
	 * @param string  $q
	 * @return string table
	 */
	function _get_table_from_query( $q ) {
		// Remove characters that can legally trail the table name
		$q = rtrim( $q, ';/-#' );
		// allow (select...) union [...] style queries. Use the first queries table name.
		$q = ltrim( $q, "\t (" );

		// Quickly match most common queries
		if ( preg_match( '/^\s*(?:'
				. 'SELECT.*?\s+FROM'
				. '|INSERT(?:\s+IGNORE)?(?:\s+INTO)?'
				. '|REPLACE(?:\s+INTO)?'
				. '|UPDATE(?:\s+IGNORE)?'
				. '|DELETE(?:\s+IGNORE)?(?:\s+FROM)?'
				. ')\s+`?(\w+)`?/is', $q, $maybe ) )
			return $maybe[1];

		// Refer to the previous query
		if ( preg_match( '/^\s*SELECT.*?\s+FOUND_ROWS\(\)/is', $q ) )
			return $this->_last_table;

		// SHOW TABLE STATUS LIKE and SHOW TABLE STATUS WHERE Name =
		if ( preg_match( '/^\s*'
				. 'SHOW\s+TABLE\s+STATUS.+(?:LIKE\s+|WHERE\s+Name\s*=\s*)'
				. '\W(\w+)\W/is', $q, $maybe ) )
			return $maybe[1];

		// Big pattern for the rest of the table-related queries in MySQL 5.0
		if ( preg_match( '/^\s*(?:'
				. '(?:EXPLAIN\s+(?:EXTENDED\s+)?)?SELECT.*?\s+FROM'
				. '|INSERT(?:\s+LOW_PRIORITY|\s+DELAYED|\s+HIGH_PRIORITY)?(?:\s+IGNORE)?(?:\s+INTO)?'
				. '|REPLACE(?:\s+LOW_PRIORITY|\s+DELAYED)?(?:\s+INTO)?'
				. '|UPDATE(?:\s+LOW_PRIORITY)?(?:\s+IGNORE)?'
				. '|DELETE(?:\s+LOW_PRIORITY|\s+QUICK|\s+IGNORE)*(?:\s+FROM)?'
				. '|DESCRIBE|DESC|EXPLAIN|HANDLER'
				. '|(?:LOCK|UNLOCK)\s+TABLE(?:S)?'
				. '|(?:RENAME|OPTIMIZE|BACKUP|RESTORE|CHECK|CHECKSUM|ANALYZE|OPTIMIZE|REPAIR).*\s+TABLE'
				. '|TRUNCATE(?:\s+TABLE)?'
				. '|CREATE(?:\s+TEMPORARY)?\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?'
				. '|ALTER(?:\s+IGNORE)?\s+TABLE'
				. '|DROP\s+TABLE(?:\s+IF\s+EXISTS)?'
				. '|CREATE(?:\s+\w+)?\s+INDEX.*\s+ON'
				. '|DROP\s+INDEX.*\s+ON'
				. '|LOAD\s+DATA.*INFILE.*INTO\s+TABLE'
				. '|(?:GRANT|REVOKE).*ON\s+TABLE'
				. '|SHOW\s+(?:.*FROM|.*TABLE)'
				. ')\s+`?(\w+)`?/is', $q, $maybe ) )
			return $maybe[1];
	}

	/**
	 * Determine the likelihood that this query could alter anything
	 *
	 * @param string  $q
	 * @return bool
	 */
	function _is_write_query( $q ) {
		// Quick and dirty: only SELECT statements are considered read-only.
		$q = ltrim( $q, "\r\n\t (" );
		return!preg_match( '/^(?:SELECT|SHOW|DESCRIBE|EXPLAIN)\s/i', $q );
	}

	/**
	 * Callbacks are executed in the order in which they are registered until one
	 * of them returns something other than null.
	 *
	 * @param string  $group
	 * @param array   $args
	 */
	function _run_callbacks( $group, $args = null ) {
		if ( !isset( $this->_callbacks[$group] ) ||
			!is_array( $this->_callbacks[$group] ) )
			return null;

		if ( !isset( $args ) ) {
			$args = array( $this );
		} elseif ( is_array( $args ) ) {
			$args[] = $this;
		} else {
			$args = array( $args, $this );
		}

		foreach ( $this->_callbacks[$group] as $func ) {
			$result = call_user_func_array( $func, $args );
			if ( isset( $result ) )
				return $result;
		}
	}

	/**
	 * Connects to server using default configuration
	 *
	 * @return resource mysql database connection
	 */
	function _db_connect_fallback() {
		if ( is_object( $this->wpdb_mixin->dbh ) )
			return $this->wpdb_mixin->dbh;
		if ( !defined( 'DB_HOST' )
			|| !defined( 'DB_USER' )
			|| !defined( 'DB_PASSWORD' )
			|| !defined( 'DB_NAME' ) )
			return $this->wpdb_mixin->bail( "We were unable to query because there was no database defined." );

		$this->wpdb_mixin->dbh = mysqli_init();

		$port = null;
		$socket = null;
		$client_flags = defined( 'MYSQL_CLIENT_FLAGS' ) ? MYSQL_CLIENT_FLAGS : 0;

		if ( WP_DEBUG ) {
			mysqli_real_connect( $this->wpdb_mixin->dbh, DB_HOST, DB_USER, DB_PASSWORD, null, $port, $socket, $client_flags );
		} else {
			@mysqli_real_connect( $this->wpdb_mixin->dbh, $host, $user, $password, null, $port, $socket, $client_flags );
		}

		if ( !is_object( $this->wpdb_mixin->dbh ) )
			return $this->wpdb_mixin->bail( "We were unable to connect to the database. (DB_HOST)" );
		if ( !mysqli_select_db( $this->wpdb_mixin->dbh, DB_NAME ) )
			return $this->wpdb_mixin->bail( "We were unable to select the database." );
		if ( !empty( $this->wpdb_mixin->charset ) ) {
			$collation_query = "SET NAMES '{$this->wpdb_mixin->charset}'";
			if ( !empty( $this->wpdb_mixin->collate ) )
				$collation_query .= " COLLATE '{$this->wpdb_mixin->collate}'";
			mysqli_query( $this->wpdb_mixin->dbh, $collation_query );
		}

		return $this->wpdb_mixin->dbh;
	}

	function w3tc_footer_comment( $strings ) {
		$append = '';
		if ( isset( $this->_current_zone['name'] ) && $this->_current_zone['name'] != 'all' )
			$append .= ' with home zone ' . $this->_current_zone['name'];

		if ( !is_null( $this->_reject_reason ) )
			$append .= ' (' . $this->_reject_reason . ')';

		$strings[] = 'Database cluster enabled ' . $append;
		return $strings;
	}

	public function w3tc_usage_statistics_of_request( $storage ) {
	}
}
