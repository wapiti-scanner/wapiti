<?php
namespace W3TC;

/**
 * W3 Fragment Cache object
 */
class Extension_FragmentCache_WpObjectCache {
	/**
	 * Internal cache array
	 *
	 * @var array
	 */
	var $cache = array();

	/**
	 * Array of global groups
	 *
	 * @var array
	 */
	var $global_groups = array( 'site-transient' );

	/**
	 * List of non-persistent groups
	 *
	 * @var array
	 */
	var $nonpersistent_groups = array();

	/**
	 * Total count of calls
	 *
	 * @var integer
	 */
	var $cache_total = 0;

	/**
	 * Cache hits count
	 *
	 * @var integer
	 */
	var $cache_hits = 0;

	/**
	 * Cache misses count
	 *
	 * @var integer
	 */
	var $cache_misses = 0;

	/**
	 * Total time
	 *
	 * @var integer
	 */
	var $time_total = 0;

	/**
	 * Store debug information of w3tc using
	 *
	 * @var array
	 */
	var $debug_info = array();

	/**
	 * Blog id of cache
	 *
	 * @var integer
	 */
	private $_blog_id;

	/**
	 * Key cache
	 *
	 * @var array
	 */
	var $_key_cache = array();

	/**
	 * Config
	 */
	var $_config = null;

	/**
	 * Caching flag
	 *
	 * @var boolean
	 */
	var $_caching = false;

	/**
	 * Cache reject reason
	 *
	 * @var string
	 */
	var $cache_reject_reason = '';

	/**
	 * Lifetime
	 *
	 * @var integer
	 */
	var $_lifetime = 0;

	/**
	 * Debug flag
	 *
	 * @var boolean
	 */
	var $_debug = false;

	private $_core;

	/**
	 * PHP5 style constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();
		$this->_lifetime = $this->_config->get_integer( array( 'fragmentcache', 'lifetime' ) );
		$this->_debug = $this->_config->get_boolean( array( 'fragmentcache', 'debug' ) );
		$this->_caching = $this->_can_cache();

		$this->_blog_id = Util_Environment::blog_id();
		$this->_core = Dispatcher::component( 'Extension_FragmentCache_Core' );
	}

	/**
	 * Get from the cache
	 *
	 * @param string  $id
	 * @param string  $group
	 * @return mixed
	 */
	function get( $id, $group = 'transient', $force = false, &$found = null ) {
		if ( $this->_debug ) {
			$time_start = Util_Debug::microtime();
		}

		$key = $this->_get_cache_key( $id );
		list( $fragment_group, $fragment_group_expiration, $fragment_group_global ) =
			$this->_fragment_group( $id, $group );
		$internal = isset( $this->cache[$fragment_group][$key] );

		if ( $internal ) {
			$found = true;
			$value = $this->cache[$fragment_group][$key];
		} elseif ( $this->_caching &&
			!in_array( $group, $this->nonpersistent_groups ) ) {
			$cache = $this->_get_cache( $fragment_group_global );
			$v = $cache->get( $key, $fragment_group );
			if ( is_array( $v ) && $v['content'] != null ) {
				$found = true;
				$value = $v['content'];
			} else
				$value = false;
		} else {
			$value = false;
		}

		if ( $value === null ) {
			$value = false;
		}

		if ( is_object( $value ) ) {
			$value = clone $value;
		}

		$this->cache[$fragment_group][$key] = $value;
		$this->cache_total++;

		if ( $value !== false ) {
			$cached = true;
			$this->cache_hits++;
		} else {
			$cached = false;
			$this->cache_misses++;
		}

		/**
		 * Add debug info
		 */
		if ( $this->_debug ) {
			$time = Util_Debug::microtime() - $time_start;
			$this->time_total += $time;

			if ( !$group ) {
				$group = 'transient';
			}

			$this->debug_info[] = array(
				'id' => $id,
				'group' => $group,
				'cached' => $cached,
				'internal' => $internal,
				'data_size' => ( $value ? strlen( serialize( $value ) ) : '' ),
				'time' => $time
			);
		}

		return $value;
	}

	/**
	 * Set to the cache
	 *
	 * @param string  $id
	 * @param mixed   $data
	 * @param string  $group
	 * @param integer $expire
	 * @return boolean
	 */
	function set( $id, $data, $group = 'transient', $expire = 0 ) {
		$key = $this->_get_cache_key( $id );

		if ( is_object( $data ) ) {
			$data = clone $data;
		}

		list( $fragment_group, $fragment_group_expiration, $fragment_group_global ) =
			$this->_fragment_group( $id, $group );
		if ( is_int( $fragment_group_expiration ) )
			$expire = $fragment_group_expiration;

		$this->cache[$fragment_group][$key] = $data;

		if ( $this->_caching &&
			!in_array( $group, $this->nonpersistent_groups ) ) {
			$cache = $this->_get_cache( $fragment_group_global );

			$v = array( 'content' => $data );
			return $cache->set( $key, $v,
				( $expire ? $expire : $this->_lifetime ), $fragment_group );
		}

		return true;
	}

	/**
	 * Delete from the cache
	 *
	 * @param string  $id
	 * @param string  $group
	 * @param bool    $force
	 * @return boolean
	 */
	function delete( $id, $group = 'transient', $force = false ) {
		if ( !$force && $this->get( $id, $group ) === false ) {
			return false;
		}
		list( $fragment_group, $fragment_group_expiration, $fragment_group_global ) =
			$this->_fragment_group( $id, $group );

		$key = $this->_get_cache_key( $id );

		unset( $this->cache[$fragment_group][$key] );

		if ( $this->_caching && !in_array( $group, $this->nonpersistent_groups ) ) {
			$cache = $this->_get_cache( $fragment_group_global );
			return $cache->delete( $key, $fragment_group );
		}

		return true;
	}

	/**
	 * Add to the cache
	 *
	 * @param string  $id
	 * @param mixed   $data
	 * @param string  $group
	 * @param integer $expire
	 * @return boolean
	 */
	function add( $id, $data, $group = 'default', $expire = 0 ) {
		if ( $this->get( $id, $group ) !== false ) {
			return false;
		}

		return $this->set( $id, $data, $group, $expire );
	}

	/**
	 * Replace in the cache
	 *
	 * @param string  $id
	 * @param mixed   $data
	 * @param string  $group
	 * @param integer $expire
	 * @return boolean
	 */
	function replace( $id, $data, $group = 'default', $expire = 0 ) {
		if ( $this->get( $id, $group ) === false ) {
			return false;
		}

		return $this->set( $id, $data, $group, $expire );
	}

	/**
	 * Reset keys
	 *
	 * @return boolean
	 */
	function reset() {
		$this->cache = array();

		return true;
	}

	/**
	 * Flush cache
	 *
	 * @return boolean
	 */
	function flush() {
		$this->cache = array();

		$cache = $this->_get_cache( false );
		$cache->flush( 'nogroup' );

		$cache = $this->_get_cache( true );
		$cache->flush( 'global-nogroup' );

		$groups = $this->_core->get_registered_fragment_groups();
		foreach ( $groups as $group => $descriptor ) {
			$cache = $this->_get_cache( $descriptor['global'] );
			$cache->flush( $group );
		}
	}

	/**
	 * Purges all transients that belong to a transient group
	 *
	 * @param string  $fragment_group fragment grouping
	 * @param bool    $global         whether flush site group or network wide, default is site specific. Use true for network wide.
	 * @return bool
	 */
	function flush_group( $fragment_group ) {
		unset( $this->cache[$fragment_group] );

		if ( $this->_caching ) {
			list( $f1, $f2, $fragment_group_global ) =
				$this->_fragment_group( $fragment_group, '' );

			$cache = $this->_get_cache( $fragment_group_global );
			return $cache->flush( $fragment_group );
		}
		return true;
	}

	/**
	 * Add global groups
	 *
	 * @param array   $groups
	 * @return void
	 */
	function add_global_groups( $groups ) {
		if ( !is_array( $groups ) ) {
			$groups = (array) $groups;
		}

		$this->global_groups = array_merge( $this->global_groups, $groups );
		$this->global_groups = array_unique( $this->global_groups );
	}

	/**
	 * Add non-persistent groups
	 *
	 * @param array   $groups
	 * @return void
	 */
	function add_nonpersistent_groups( $groups ) {
		if ( !is_array( $groups ) ) {
			$groups = (array) $groups;
		}

		$this->nonpersistent_groups = array_merge( $this->nonpersistent_groups, $groups );
		$this->nonpersistent_groups = array_unique( $this->nonpersistent_groups );
	}

	/**
	 * Increment numeric cache item's value
	 *
	 * @param int|string $key    The cache key to increment
	 * @param int     $offset The amount by which to increment the item's value. Default is 1.
	 * @param string  $group  The group the key is in.
	 * @return bool|int False on failure, the item's new value on success.
	 */
	function incr( $key, $offset = 1, $group = 'default' ) {
		$value = $this->get( $key, $group );
		if ( $value === false )
			return false;

		if ( !is_numeric( $value ) )
			$value = 0;

		$offset = (int) $offset;
		$value += $offset;

		if ( $value < 0 )
			$value = 0;
		$this->replace( $key, $value, $group );
		return $value;
	}

	/**
	 * Decrement numeric cache item's value
	 *
	 * @param int|string $key    The cache key to increment
	 * @param int     $offset The amount by which to decrement the item's value. Default is 1.
	 * @param string  $group  The group the key is in.
	 * @return bool|int False on failure, the item's new value on success.
	 */
	function decr( $key, $offset = 1, $group = 'default' ) {
		$value = $this->get( $key, $group );
		if ( $value === false )
			return false;

		if ( !is_numeric( $value ) )
			$value = 0;

		$offset = (int) $offset;
		$value -= $offset;

		if ( $value < 0 )
			$value = 0;
		$this->replace( $key, $value, $group );
		return $value;
	}

	/**
	 * Switches context to another blog
	 *
	 * @param integer $blog_id
	 */
	function switch_blog( $blog_id ) {
		$this->reset();
		$this->_blog_id = $blog_id;
	}

	/**
	 * Returns cache key
	 *
	 * @param string  $id
	 * @param string  $group
	 * @return string
	 */
	function _get_cache_key( $id ) {
		return md5( $id );
	}

	/**
	 * Returns cache object
	 *
	 * @param null    $blog_id
	 * @param string  $group
	 * @return W3_Cache_Base
	 */
	function _get_cache( $global = false ) {
		static $cache = array();

		if ( !$global )
			$blog_id = $this->_blog_id;
		else
			$blog_id = 0;

		if ( !isset( $cache[$blog_id] ) ) {
			$engine = $this->_config->get_string( array( 'fragmentcache', 'engine' ) );

			switch ( $engine ) {
			case 'memcached':
				$engineConfig = array(
					'servers' => $this->_config->get_array( array( 'fragmentcache', 'memcached.servers' ) ),
					'persistent' => $this->_config->get_boolean( array( 'fragmentcache', 'memcached.persistent' ) ),
					'aws_autodiscovery' => $this->_config->get_boolean( array( 'fragmentcache', 'memcached.aws_autodiscovery' ) ),
					'username' => $this->_config->get_string( array( 'fragmentcache', 'memcached.username' ) ),
					'password' => $this->_config->get_string( array( 'fragmentcache', 'memcached.password' ) )
				);
				break;

			case 'redis':
				$engineConfig = array(
					'servers' => $this->_config->get_array( array( 'fragmentcache', 'redis.servers' ) ),
					'verify_tls_certificates' => $this->_config->get_boolean( array( 'fragmentcache', 'redis.verify_tls_certificates' ) ),
					'persistent' => $this->_config->get_boolean( array( 'fragmentcache', 'redis.persistent' ) ),
					'timeout' => $this->_config->get_integer( array( 'fragmentcache', 'redis.timeout' ) ),
					'retry_interval' => $this->_config->get_integer( array( 'fragmentcache', 'redis.retry_interval' ) ),
					'read_timeout' => $this->_config->get_integer( array( 'fragmentcache', 'redis.read_timeout' ) ),
					'dbid' => $this->_config->get_integer( array( 'fragmentcache', 'redis.dbid' ) ),
					'password' => $this->_config->get_string( array( 'fragmentcache', 'redis.password' ) )
				);
				break;

			case 'file':
				$engineConfig = array(
					'section' => 'fragment',
					'locking' => $this->_config->get_boolean( array( 'fragmentcache', 'file.locking' ) ),
					'flush_timelimit' => $this->_config->get_integer( 'timelimit.cache_flush' )
				);
				break;

			default:
				$engineConfig = array();
			}
			$engineConfig['blog_id'] = $blog_id;
			$engineConfig['module'] = 'fragmentcache';
			$engineConfig['host'] = Util_Environment::host();
			$engineConfig['instance_id'] = Util_Environment::instance_id();

			$cache[$blog_id] = Cache::instance( $engine, $engineConfig );
		}

		return $cache[$blog_id];
	}

	/**
	 * Check if caching allowed on init
	 *
	 * @return boolean
	 */
	function _can_cache() {
		return true;
	}

	/**
	 * Returns debug info
	 *
	 * @return string
	 */
	public function w3tc_footer_comment( $strings ) {
		$append = ( $this->cache_reject_reason != '' ?
			sprintf( ' (%s)', $this->cache_reject_reason ) :'' );

		$strings[] = sprintf(
			__( 'Fragment Caching %d/%d fragments using %s%s', 'w3-total-cache' ),
			$this->cache_hits, $this->cache_total,
			Cache::engine_name( $this->_config->get_string( array( 'fragmentcache', 'engine' ) ) ),
			$append );

		if ( $this->_config->get_boolean( array( 'fragmentcache', 'debug' ) ) ) {
			$strings[] = '';
			$strings[] = 'Fragment Cache debug info:';
			$strings[] = sprintf( "%s%s", str_pad( 'Caching: ', 20 ), ( $this->_caching ? 'enabled' : 'disabled' ) );

			$strings[] = sprintf( "%s%d", str_pad( 'Total calls: ', 20 ), $this->cache_total );
			$strings[] = sprintf( "%s%d", str_pad( 'Cache hits: ', 20 ), $this->cache_hits );
			$strings[] = sprintf( "%s%d", str_pad( 'Cache misses: ', 20 ), $this->cache_misses );
			$strings[] = sprintf( "%s%.4f", str_pad( 'Total time: ', 20 ), $this->time_total );

			$strings[] = "W3TC Fragment Cache info:";
			$strings[] = sprintf( "%s | %s | %s | %s | %s | %s| %s| %s",
				str_pad( '#', 5, ' ', STR_PAD_LEFT ),
				str_pad( 'Status', 15, ' ', STR_PAD_BOTH ),
				str_pad( 'Source', 15, ' ', STR_PAD_BOTH ),
				str_pad( 'Data size (b)', 13, ' ', STR_PAD_LEFT ),
				str_pad( 'Query time (s)', 14, ' ', STR_PAD_LEFT ),
				str_pad( 'Group', 14, ' ', STR_PAD_LEFT ),
				str_pad( 'Accessible', 10, ' ', STR_PAD_LEFT ),
				'Transient ID' );

			foreach ( $this->debug_info as $index => $debug ) {
				list( $fragment_group, $fragment_group_expiration, $fragment_group_global ) =
					$this->_fragment_group( $debug['id'], $debug['group'] );
				$strings[] = sprintf( "%s | %s | %s | %s | %s | %s| %s| %s",
					str_pad( $index + 1, 5, ' ', STR_PAD_LEFT ),
					str_pad( ( $debug['cached'] ? 'cached' : 'not cached' ), 15, ' ', STR_PAD_BOTH ),
					str_pad( ( $debug['internal'] ? 'internal' : 'persistent' ), 15, ' ', STR_PAD_BOTH ),
					str_pad( $debug['data_size'], 13, ' ', STR_PAD_LEFT ),
					str_pad( round( $debug['time'], 4 ), 14, ' ', STR_PAD_LEFT ),
					str_pad( $fragment_group, 14, ' ', STR_PAD_LEFT ),
					str_pad( ( $debug['group'] == 'transient' ? 'site' : 'network' ), 10, ' ', STR_PAD_LEFT ),
					$debug['id'] );
			}
			$strings[] = '';
		}

		return $strings;
	}

	/**
	 * Returns the group part of a transient/site-transient id.
	 * Uses registered fragment groups to identify it.
	 *
	 * @param unknown $id
	 * @return string
	 */
	private function _fragment_group( $id, $group ) {
		if ( empty( $id ) )
			return array( 'nogroup', 0, false );
		$groups = $this->_core->get_registered_fragment_groups();
		$use_group = '';
		$length = 0;
		foreach ( $groups as $group => $descriptor ) {
			if ( strpos( $id, $group ) !== false ) {
				if ( strlen( $group ) > $length ) {
					$length = strlen( $group );
					$use_group = array( $group, $descriptor['expiration'],
						$descriptor['global'] );
				}
			}
		}
		if ( $use_group )
			return $use_group;

		if ( $group == 'site-transient' )
			return array( 'global-nogroup', 0, true );

		return array( 'nogroup', 0, false );
	}

	public function w3tc_usage_statistics_of_request( $storage ) {
		$storage->counter_add( 'fragmentcache_calls_total', $this->cache_total );
		$storage->counter_add( 'fragmentcache_calls_hits', $this->cache_hits );
	}
}
