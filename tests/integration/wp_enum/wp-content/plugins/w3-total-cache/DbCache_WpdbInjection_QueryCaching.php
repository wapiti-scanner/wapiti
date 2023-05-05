<?php
/**
 * File: DbCache_WpdbInjection_QueryCaching.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: DbCache_WpdbInjection_QueryCaching
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 * phpcs:disable PSR2.Methods.MethodDeclaration.Underscore
 */
class DbCache_WpdbInjection_QueryCaching extends DbCache_WpdbInjection {
	/**
	 * Queries total.
	 *
	 * @var int
	 */
	public $query_total = 0;

	/**
	 * Query cache hits.
	 *
	 * @var int
	 */
	public $query_hits = 0;

	/**
	 * Query cache misses.
	 *
	 * @var int
	 */
	public $query_misses = 0;

	/**
	 * Time total taken by queries, in microsecs.
	 *
	 * @var int
	 */
	public $time_total = 0;

	/**
	 * Config.
	 *
	 * @var Config
	 */
	public $_config = null;

	/**
	 * Lifetime.
	 *
	 * @var int
	 */
	public $_lifetime = null;

	/**
	 * Number of cache flushes during http request processing.
	 *
	 * @var int
	 */
	private $cache_flushes = 0;

	/**
	 * Request-global cache reject reason.
	 *
	 * @var string
	 */
	private $cache_reject_reason = null;

	/**
	 * Request-global check reject scope.
	 *
	 * @var bool
	 */
	private $cache_reject_request_wide = false;

	/**
	 * Debug flag.
	 *
	 * @var bool
	 */
	private $debug = false;

	/**
	 * Reject log flag.
	 *
	 * @var bool
	 */
	private $reject_logged = false;

	/**
	 * Log filehandle flag.
	 *
	 * @var bool
	 */
	private $log_filehandle = false;

	/**
	 * Reject constants flag.
	 *
	 * @var bool
	 */
	private $reject_constants = false;

	/**
	 * Use filters flag.
	 *
	 * @var bool
	 */
	private $use_filters = false;

	/**
	 * Result of check if caching is possible at the level of current http request.
	 *
	 * @var bool
	 */
	private $can_cache_once_per_request_result = null;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$c                      = Dispatcher::config();
		$this->_config          = $c;
		$this->_lifetime        = $c->get_integer( 'dbcache.lifetime' );
		$this->debug            = $c->get_boolean( 'dbcache.debug' );
		$this->reject_logged    = $c->get_boolean( 'dbcache.reject.logged' );
		$this->reject_constants = $c->get_array( 'dbcache.reject.constants' );
		$this->use_filters      = $this->_config->get_boolean( 'dbcache.use_filters' );
	}

	/**
	 * Executes query.
	 *
	 * @param string $query Query.
	 * @return int
	 */
	public function query( $query ) {
		if ( ! $this->wpdb_mixin->ready ) {
			return $this->next_injection->query( $query );
		}

		$reject_reason     = '';
		$is_cache_hit      = false;
		$data              = false;
		$time_total        = 0;
		$group             = '';
		$flush_after_query = false;

		$this->query_total++;

		$caching = $this->_can_cache( $query, $reject_reason );
		if ( preg_match( '~^\s*start transaction\b~is', $query ) ) {
			$this->cache_reject_reason = 'transaction';
			$reject_reason             = $this->cache_reject_reason;
			$caching                   = false;
		}

		if ( preg_match( '~^\s*insert\b|^\s*delete\b|^\s*update\b|^\s*replace\b|^\s*commit\b|^\s*truncate\b|^\s*drop\b|^\s*create\b~is', $query ) ) {
			$this->cache_reject_reason = 'modification query';
			$reject_reason             = $this->cache_reject_reason;
			$caching                   = false;
			$flush_after_query         = true;
		}

		if ( $this->use_filters && function_exists( 'apply_filters' ) ) {
			$reject_reason = apply_filters(
				'w3tc_dbcache_can_cache_sql',
				( $caching ? '' : $reject_reason ),
				$query
			);

			$caching = empty( $reject_reason );
		}

		if ( $caching ) {
			$this->wpdb_mixin->timer_start();
			$cache      = $this->_get_cache();
			$group      = $this->_get_group( $query );
			$data       = $cache->get( md5( $query ), $group );
			$time_total = $this->wpdb_mixin->timer_stop();
		}

		if ( is_array( $data ) ) {
			$is_cache_hit = true;
			$this->query_hits++;

			$this->wpdb_mixin->last_error  = $data['last_error'];
			$this->wpdb_mixin->last_query  = $data['last_query'];
			$this->wpdb_mixin->last_result = $data['last_result'];
			$this->wpdb_mixin->col_info    = $data['col_info'];
			$this->wpdb_mixin->num_rows    = $data['num_rows'];
			$return_val                    = $data['return_val'];
		} else {
			$this->query_misses++;

			$this->wpdb_mixin->timer_start();
			$return_val = $this->next_injection->query( $query );
			$time_total = $this->wpdb_mixin->timer_stop();

			if ( $flush_after_query ) {
				$group = $this->_get_group( $query );

				$this->_flush_cache_for_sql_group(
					$group,
					array( 'modification_query' => $query )
				);
			}

			if ( $caching ) {
				$data = array(
					'last_error'  => $this->wpdb_mixin->last_error,
					'last_query'  => $this->wpdb_mixin->last_query,
					'last_result' => $this->wpdb_mixin->last_result,
					'col_info'    => $this->wpdb_mixin->col_info,
					'num_rows'    => $this->wpdb_mixin->num_rows,
					'return_val'  => $return_val,
				);

				$cache = $this->_get_cache();
				$group = $this->_get_group( $query );

				$filter_data = array(
					'query'      => $query,
					'group'      => $group,
					'content'    => $data,
					'expiration' => $this->_lifetime,
				);

				if ( $this->use_filters && function_exists( 'apply_filters' ) ) {
					$filter_data = apply_filters( 'w3tc_dbcache_cache_set', $filter_data );
				}

				$cache->set(
					md5( $filter_data['query'] ),
					$filter_data['content'],
					$filter_data['expiration'],
					$filter_data['group']
				);
			}
		}

		if ( $this->debug ) {
			$this->log_query(
				array(
					gmdate( 'r' ),
					strtr(
						isset( $_SERVER['REQUEST_URI'] ) ?
							filter_var( stripslashes( $_SERVER['REQUEST_URI'] ), FILTER_SANITIZE_URL ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
						"<>\r\n",
						'..  '
					),
					strtr( $query, "<>\r\n", '..  ' ), // query.
					(int) ( $time_total * 1000000 ), // time_total in seconds.
					$reject_reason, // reason.
					$is_cache_hit, // cached.
					( $data ? strlen( serialize( $data ) ) : 0 ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- data size
					strtr( $group, "<>\r\n", '..  ' ), // group.
				)
			);
		}

		$this->time_total += $time_total;

		return $return_val;
	}

	/**
	 * Escape.
	 *
	 * @param array $data Data.
	 */
	public function _escape( $data ) {
		return $this->next_injection->_escape( $data );
	}

	/**
	 * Prepare.
	 *
	 * @param string $query Query.
	 * @param array  $args  Arguments.
	 */
	public function prepare( $query, $args ) {
		return $this->next_injection->prepare( $query, $args );
	}

	/**
	 * Initializes object, calls underlying processor.
	 */
	public function initialize() {
		return $this->next_injection->initialize();
	}

	/**
	 * Insert a row into a table.
	 *
	 * @param string       $table  Table.
	 * @param array        $data   Data.
	 * @param array|string $format Format.
	 *
	 * @return int|false
	 */
	public function insert( $table, $data, $format = null ) {
		return $this->next_injection->insert( $table, $data, $format );
	}

	/**
	 * Replace a row into a table.
	 *
	 * @param string       $table  Table.
	 * @param array        $data   Data.
	 * @param array|string $format Format.
	 *
	 * @return int|false
	 */
	public function replace( $table, $data, $format = null ) {
		$group = $this->_get_group( $table );
		$this->_flush_cache_for_sql_group(
			$group,
			array( 'wpdb_replace' => $table )
		);

		return $this->next_injection->replace( $table, $data, $format );
	}

	/**
	 * Update a row in the table
	 *
	 * @param string       $table        Table.
	 * @param array        $data         Data.
	 * @param array        $where        Where.
	 * @param array|string $format       Format.
	 * @param array|string $where_format Format where.
	 *
	 * @return int|false
	 */
	public function update( $table, $data, $where, $format = null, $where_format = null ) {
		$group = $this->_get_group( $table );
		$this->_flush_cache_for_sql_group( $group, array( 'wpdb_update' => $table ) );
		return $this->next_injection->update( $table, $data, $where, $format, $where_format );
	}

	/**
	 * Deletes from table.
	 *
	 * @param string       $table        Table.
	 * @param array        $where        Where.
	 * @param array|string $where_format Format where.
	 *
	 * @return int|false
	 */
	public function delete( $table, $where, $where_format = null ) {
		$group = $this->_get_group( $table );
		$this->_flush_cache_for_sql_group( $group, array( 'wpdb_delete' => $table ) );
		return $this->next_injection->delete( $table, $where, $where_format );
	}

	/**
	 * Flushes cache.
	 *
	 * @param array $extras Extra arguments.
	 *
	 * @return bool
	 */
	public function flush_cache( $extras = array() ) {
		return $this->_flush_cache_for_sql_group( 'remaining', $extras );
	}

	/**
	 * Flush cache for SQL groups.
	 *
	 * @access private
	 *
	 * @param string $group  Group.
	 * @param array  $extras Extra arguments.
	 *
	 * @return bool
	 */
	private function _flush_cache_for_sql_group( $group, $extras = array() ) {
		$this->wpdb_mixin->timer_start();

		if ( $this->debug ) {
			$filename = Util_Debug::log(
				'dbcache',
				'flushing based on sqlquery group ' . $group .
				' with extras ' . wp_json_encode( $extras )
			);
		}
		if ( $this->_config->get_boolean( 'dbcache.debug_purge' ) ) {
			Util_Debug::log_purge(
				'dbcache',
				'_flush_cache_for_sql_group',
				array( $group, $extras )
			);
		}

		$cache        = $this->_get_cache();
		$flush_groups = $this->_get_flush_groups( $group, $extras );
		$v            = true;

		$this->cache_flushes++;

		foreach ( $flush_groups as $f_group => $nothing ) {
			if ( $this->debug ) {
				$filename = Util_Debug::log( 'dbcache', 'flush group ' . $f_group );
			}
			$v &= $cache->flush( $f_group );
		}

		$this->time_total += $this->wpdb_mixin->timer_stop();

		return $v;
	}

	/**
	 * Returns cache object.
	 *
	 * @return W3_Cache_Base
	 */
	public function _get_cache() {
		static $cache = array();

		if ( ! isset( $cache[0] ) ) {
			$engine = $this->_config->get_string( 'dbcache.engine' );

			switch ( $engine ) {
				case 'memcached':
					$engine_config = array(
						'servers'           => $this->_config->get_array( 'dbcache.memcached.servers' ),
						'persistent'        => $this->_config->get_boolean( 'dbcache.memcached.persistent' ),
						'aws_autodiscovery' => $this->_config->get_boolean( 'dbcache.memcached.aws_autodiscovery' ),
						'username'          => $this->_config->get_string( 'dbcache.memcached.username' ),
						'password'          => $this->_config->get_string( 'dbcache.memcached.password' ),
						'binary_protocol'   => $this->_config->get_boolean( 'dbcache.memcached.binary_protocol' ),
					);
					break;

				case 'redis':
					$engine_config = array(
						'servers'                 => $this->_config->get_array( 'dbcache.redis.servers' ),
						'verify_tls_certificates' => $this->_config->get_boolean( 'dbcache.redis.verify_tls_certificates' ),
						'persistent'              => $this->_config->get_boolean( 'dbcache.redis.persistent' ),
						'timeout'                 => $this->_config->get_integer( 'dbcache.redis.timeout' ),
						'retry_interval'          => $this->_config->get_integer( 'dbcache.redis.retry_interval' ),
						'read_timeout'            => $this->_config->get_integer( 'dbcache.redis.read_timeout' ),
						'dbid'                    => $this->_config->get_integer( 'dbcache.redis.dbid' ),
						'password'                => $this->_config->get_string( 'dbcache.redis.password' ),
					);
					break;

				case 'file':
					$engine_config = array(
						'use_wp_hash'     => true,
						'section'         => 'db',
						'locking'         => $this->_config->get_boolean( 'dbcache.file.locking' ),
						'flush_timelimit' => $this->_config->get_integer( 'timelimit.cache_flush' ),
					);
					break;

				default:
					$engine_config = array();
			}
			$engine_config['module']      = 'dbcache';
			$engine_config['host']        = Util_Environment::host();
			$engine_config['instance_id'] = Util_Environment::instance_id();

			$cache[0] = Cache::instance( $engine, $engine_config );
		}

		return $cache[0];
	}

	/**
	 * Check if can cache sql.
	 *
	 * @param string $sql                 SQL query.
	 * @param string $cache_reject_reason Cache reject reason.
	 *
	 * @return boolean
	 */
	public function _can_cache( $sql, &$cache_reject_reason ) {
		/**
		 * Skip if request-wide reject reason specified.
		 * Note - as a result requedt-wide checks are done only once per request.
		 */
		if ( ! is_null( $this->cache_reject_reason ) ) {
			$cache_reject_reason             = $this->cache_reject_reason;
			$this->cache_reject_request_wide = true;
			return false;
		}

		/**
		 * Do once-per-request check if needed.
		 */
		if ( is_null( $this->can_cache_once_per_request_result ) ) {
			$this->can_cache_once_per_request_result = $this->_can_cache_once_per_request();
			if ( ! $this->can_cache_once_per_request_result ) {
				$this->cache_reject_request_wide = true;
				return false;
			}
		}

		/**
		 * Check for constants.
		 */
		foreach ( $this->reject_constants as $name ) {
			if ( defined( $name ) && constant( $name ) ) {
				$this->cache_reject_reason = $name . ' constant defined';
				$cache_reject_reason       = $this->cache_reject_reason;

				return false;
			}
		}

		/**
		 * Check for AJAX requests.
		 */
		$ajax_skip = false;

		if ( defined( 'DOING_AJAX' ) ) {
			$http_referer = isset( $_SERVER['HTTP_REFERER'] ) ?
				filter_var( stripslashes( $_SERVER['HTTP_REFERER'] ), FILTER_SANITIZE_URL ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

			// wp_admin is always defined for ajax requests, check by referrer.
			if ( strpos( $http_referer, '/wp-admin/' ) === false ) {
				$ajax_skip = true;
			}
		}

		/**
		 * Skip if admin.
		 */
		if ( defined( 'WP_ADMIN' ) && ! $ajax_skip ) {
			$this->cache_reject_reason = 'WP_ADMIN';
			$cache_reject_reason       = $this->cache_reject_reason;

			return false;
		}

		/**
		 * Skip if SQL is rejected.
		 */
		if ( ! $this->_check_sql( $sql ) ) {
			$cache_reject_reason = 'query not cacheable';

			return false;
		}

		/**
		 * Skip if user is logged in.
		 */
		if ( $this->reject_logged && ! $this->_check_logged_in() ) {
			$this->cache_reject_reason = 'user.logged_in';
			$cache_reject_reason       = $this->cache_reject_reason;

			return false;
		}

		return true;
	}

	/**
	 * Check if can cache sql, checks which have constant results during whole request.
	 *
	 * @return bool
	 */
	public function _can_cache_once_per_request() {
		/**
		 * Skip if disabled
		 */
		if ( ! $this->_config->get_boolean( 'dbcache.enabled' ) ) {
			$this->cache_reject_reason = 'dbcache.disabled';

			return false;
		}

		/**
		 * Skip if request URI is rejected
		 */
		if ( ! $this->_check_request_uri() ) {
			$this->cache_reject_reason = 'request';
			return false;
		}

		/**
		 * Skip if cookie is rejected
		 */
		if ( ! $this->_check_cookies() ) {
			$this->cache_reject_reason = 'cookie';
			return false;
		}

		return true;
	}

	/**
	 * Check SQL
	 *
	 * @param string $sql SQL query.
	 *
	 * @return bool
	 */
	public function _check_sql( $sql ) {

		$auto_reject_strings = $this->_config->get_array( 'dbcache.reject.words' );

		if ( preg_match( '~' . implode( '|', $auto_reject_strings ) . '~is', $sql ) ) {
			return false;
		}

		$reject_sql = $this->_config->get_array( 'dbcache.reject.sql' );

		foreach ( $reject_sql as $expr ) {
			$expr = trim( $expr );
			$expr = str_replace( '{prefix}', $this->wpdb_mixin->prefix, $expr );
			if ( ! empty( $expr ) && preg_match( '~' . $expr . '~i', $sql ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check request URI
	 *
	 * @return boolean
	 */
	public function _check_request_uri() {
		$auto_reject_uri = array(
			'wp-login',
			'wp-register',
		);

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ?
			filter_var( stripslashes( $_SERVER['REQUEST_URI'] ), FILTER_SANITIZE_URL ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

		foreach ( $auto_reject_uri as $uri ) {
			if ( strstr( $request_uri, $uri ) !== false ) {
				return false;
			}
		}

		$reject_uri = $this->_config->get_array( 'dbcache.reject.uri' );
		$reject_uri = array_map( array( '\W3TC\Util_Environment', 'parse_path' ), $reject_uri );

		foreach ( $reject_uri as $expr ) {
			$expr = trim( $expr );
			if ( ! empty( $expr ) && preg_match( '~' . $expr . '~i', $request_uri ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Checks for WordPress cookies.
	 *
	 * @return bool
	 */
	public function _check_cookies() {
		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( 'wordpress_test_cookie' === $cookie_name ) {
				continue;
			}
			if ( preg_match( '/^wp-postpass|^comment_author/', $cookie_name ) ) {
				return false;
			}
		}

		foreach ( $this->_config->get_array( 'dbcache.reject.cookie' ) as $reject_cookie ) {
			foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
				if ( strstr( $cookie_name, $reject_cookie ) !== false ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Check if user is logged in.
	 *
	 * @return bool
	 */
	public function _check_logged_in() {
		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( strpos( $cookie_name, 'wordpress_logged_in' ) === 0 ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get group.
	 *
	 * @access private
	 *
	 * @param string $sql SQL query.
	 *
	 * @return string
	 */
	private function _get_group( $sql ) {
		$sql = strtolower( $sql );

		// Collect list of tables used in query.
		if ( preg_match_all( '~(^|[\s,`])' . $this->wpdb_mixin->prefix . '([0-9a-zA-Z_]+)~i', $sql, $m ) ) {
			$tables = array_unique( $m[2] );
		} else {
			$tables = array();
		}

		if ( $this->contains_only_tables( $tables, array( 'options' => '*' ) ) ) {
			$group = 'options';
		} elseif (
			$this->contains_only_tables(
				$tables,
				array(
					'comments'     => '*',
					'commentsmeta' => '*',
				)
			) ) {
			$group = 'comments';
		} elseif ( count( $tables ) <= 1 ) {
			$group = 'singletables';   // Request with single table affected.
		} else {
			$group = 'remaining';
		}

		if ( $this->use_filters && function_exists( 'apply_filters' ) ) {
			$group = apply_filters( 'w3tc_dbcache_get_sql_group', $group, $sql, $tables );
		}

		return $group;
	}

	/**
	 * Contains only tables.
	 *
	 * @accress private
	 *
	 * @param array $tables  Tables.
	 *
	 * @param array $allowed Allowed.
	 */
	private function contains_only_tables( $tables, $allowed ) {
		if ( empty( $tables ) ) {
			return false;
		}

		foreach ( $tables as $t ) {
			if ( ! isset( $allowed[ $t ] ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get flush groups
	 *
	 * @access private
	 *
	 * @param string $group  Group.
	 *
	 * @param array  $extras Extra arguments.
	 */
	private function _get_flush_groups( $group, $extras = array() ) {
		$groups_to_flush = array();

		switch ( $group ) {
			case 'remaining':
			case 'singletables':
				$groups_to_flush = array(
					'remaining'    => '*',
					'options'      => '*',
					'comments'     => '*',
					'singletables' => '*',
				);
				break;
			/**
			 * Options are updated on each second request,
			 * ignore by default probability that SELECTs with joins with options are critical and don't flush "remaining".
			 * That can be changed by w3tc_dbcache_get_flush_groups filter.
			 */
			case 'options':
				$groups_to_flush = array( $group => '*' );
				break;
			default:
				$groups_to_flush = array(
					$group      => '*',
					'remaining' => '*',
				);
		}

		if ( $this->use_filters && function_exists( 'apply_filters' ) ) {
			$groups_to_flush = apply_filters( 'w3tc_dbcache_get_flush_groups', $groups_to_flush, $group, $extras );
		}

		return $groups_to_flush;
	}

	/**
	 * Get reject reason.
	 *
	 * @return string
	 */
	public function get_reject_reason() {
		if ( is_null( $this->cache_reject_reason ) ) {
			return '';
		}

		$request_wide_string = $this->cache_reject_request_wide ?
			( function_exists( '__' ) ? __( 'Request-wide ', 'w3-total-cache' ) : 'Request ' ) : '';

		return $request_wide_string . $this->_get_reject_reason_message( $this->cache_reject_reason );
	}

	/**
	 * Get reject reason message.
	 *
	 * @param string $key Key.
	 *
	 * @return string|void
	 */
	private function _get_reject_reason_message( $key ) {
		if ( ! function_exists( '__' ) ) {
			return $key;
		}

		switch ( $key ) {
			case 'dbcache.disabled':
				return __( 'Database caching is disabled', 'w3-total-cache' );
			case 'DONOTCACHEDB':
				return __( 'DONOTCACHEDB constant is defined', 'w3-total-cache' );
			case 'DOING_AJAX':
				return __( 'Doing AJAX', 'w3-total-cache' );
			case 'request':
				return __( 'Request URI is rejected', 'w3-total-cache' );
			case 'cookie':
				return __( 'Cookie is rejected', 'w3-total-cache' );
			case 'DOING_CRONG':
				return __( 'Doing cron', 'w3-total-cache' );
			case 'APP_REQUEST':
				return __( 'Application request', 'w3-total-cache' );
			case 'XMLRPC_REQUEST':
				return __( 'XMLRPC request', 'w3-total-cache' );
			case 'WP_ADMIN':
				return __( 'wp-admin', 'w3-total-cache' );
			case 'SHORTINIT':
				return __( 'Short init', 'w3-total-cache' );
			case 'query':
				return __( 'Query is rejected', 'w3-total-cache' );
			case 'user.logged_in':
				return __( 'User is logged in', 'w3-total-cache' );
			default:
				return $key;
		}
	}

	/**
	 * Footer comment.
	 *
	 * @param array $strings Strings.
	 *
	 * @return array
	 */
	public function w3tc_footer_comment( $strings ) {
		$reject_reason = $this->get_reject_reason();
		$append        = empty( $reject_reason ) ? '' : sprintf( ' (%1$s)', $reject_reason );

		if ( $this->query_hits ) {
			$strings[] = sprintf(
				// translators: 1: Query hits, 2: Total queries, 3: Total time, 4: Engine name, 5: Reject reason.
				__( 'Database Caching %1$d/%2$d queries in %3$.3f seconds using %4$s%5$s', 'w3-total-cache' ),
				$this->query_hits,
				$this->query_total,
				$this->time_total,
				Cache::engine_name( $this->_config->get_string( 'dbcache.engine' ) ),
				$append
			);
		} else {
			$strings[] = sprintf(
				// translators: 1: Engine name, 2: Reject reason.
				__( 'Database Caching using %1$s%2$s', 'w3-total-cache' ),
				Cache::engine_name( $this->_config->get_string( 'dbcache.engine' ) ),
				$append
			);
		}

		if ( $this->debug ) {
			$strings[] = '';
			$strings[] = __( 'Db cache debug info:', 'w3-total-cache' );
			$strings[] = sprintf( '%1$s%2$d', str_pad( __( 'Total queries: ', 'w3-total-cache' ), 20 ), $this->query_total );
			$strings[] = sprintf( '%1$s%2$d', str_pad( __( 'Cached queries: ', 'w3-total-cache' ), 20 ), $this->query_hits );
			$strings[] = sprintf( '%1$s%2$.4f', str_pad( __( 'Total query time: ', 'w3-total-cache' ), 20 ), $this->time_total );
		}

		if ( $this->log_filehandle ) {
			fclose( $this->log_filehandle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fclose
			$this->log_filehandle = false;
		}
		return $strings;
	}

	/**
	 * Usage statistics of request.
	 *
	 * @param object $storage Storage object.
	 *
	 * @return void
	 */
	public function w3tc_usage_statistics_of_request( $storage ) {
		$storage->counter_add( 'dbcache_calls_total', $this->query_total );
		$storage->counter_add( 'dbcache_calls_hits', $this->query_hits );
		$storage->counter_add( 'dbcache_flushes', $this->cache_flushes );
		$time_ms = (int) ( $this->time_total * 1000 );
		$storage->counter_add( 'dbcache_time_ms', $time_ms );
	}

	/**
	 * Log query.
	 *
	 * @access private
	 *
	 * @param string $line Line to add.
	 *
	 * @return void
	 */
	private function log_query( $line ) {
		if ( ! $this->log_filehandle ) {
			$filename             = Util_Debug::log_filename( 'dbcache-queries' );
			$this->log_filehandle = fopen( $filename, 'a' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fopen
		}

		fputcsv( $this->log_filehandle, $line, "\t" );
	}
}
