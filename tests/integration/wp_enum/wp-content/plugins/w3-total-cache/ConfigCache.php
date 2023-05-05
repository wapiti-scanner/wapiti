<?php
/**
 * File: ConfigCache.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Provides access to config cache, used mostly when config is stored in
 * database to not issue config loading database queries on each http request
 */
class ConfigCache {
	/**
	 * Reads config from config cache
	 *
	 * @param int  $blog_id Blog ID.
	 * @param bool $preview Preview flag.
	 *
	 * @return array|null
	 */
	public static function util_array_from_storage( $blog_id, $preview ) {
		$cache = self::get_cache();

		$config = $cache->get( self::get_key( $blog_id, $preview ) );
		if ( is_array( $config ) ) {
			return $config;
		}

		return null;
	}

	/**
	 * Removes config cache entry so that it can be read from original source
	 * on next attempt
	 *
	 * @param int  $blog_id Blog ID.
	 * @param bool $preview Preview flag.
	 */
	public static function remove_item( $blog_id, $preview ) {
		$cache = self::get_cache();

		$cache->hard_delete( self::get_key( $blog_id, false ) );
		$cache->hard_delete( self::get_key( $blog_id, true ) );
	}

	/**
	 * Saves config cache entry.
	 *
	 * @param int   $blog_id Blog ID.
	 * @param bool  $preview Preview flag.
	 * @param mixed $data Data.
	 */
	public static function save_item( $blog_id, $preview, $data ) {
		$cache = self::get_cache();

		$cache->set( self::get_key( $blog_id, $preview ), $data );
	}

	/**
	 * Retrieves cache instance.
	 *
	 * @return object
	 */
	private static function get_cache() {
		static $cache = null;

		if ( ! is_null( $cache ) ) {
			return $cache;
		}

		switch ( W3TC_CONFIG_CACHE_ENGINE ) {
			case 'memcached':
				$engine_config = array(
					'servers'           =>
						explode( ',', W3TC_CONFIG_CACHE_MEMCACHED_SERVERS ),
					'persistent'        =>
						( defined( 'W3TC_CONFIG_CACHE_MEMCACHED_PERSISTENT' ) ?
							W3TC_CONFIG_CACHE_MEMCACHED_PERSISTENT : true ),
					'aws_autodiscovery' =>
						( defined( 'W3TC_CONFIG_CACHE_MEMCACHED_AWS_AUTODISCOVERY' ) ?
							W3TC_CONFIG_CACHE_MEMCACHED_AWS_AUTODISCOVERY : false ),
					'username'          =>
						( defined( 'W3TC_CONFIG_CACHE_MEMCACHED_USERNAME' ) ?
							W3TC_CONFIG_CACHE_MEMCACHED_USERNAME : '' ),
					'password'          =>
						( defined( 'W3TC_CONFIG_CACHE_MEMCACHED_PASSWORD' ) ?
							W3TC_CONFIG_CACHE_MEMCACHED_PASSWORD : '' ),
					'key_version_mode'  => 'disabled',
				);
				break;
			case 'redis':
				$engine_config = array(
					'servers'                 =>
						explode( ',', W3TC_CONFIG_CACHE_REDIS_SERVERS ),
					'verify_tls_certificates' =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_VERIFY_TLS_CERTIFICATES' ) ?
							W3TC_CONFIG_CACHE_REDIS_VERIFY_TLS_CERTIFICATES : true ),
					'persistent'              =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_PERSISTENT' ) ?
							W3TC_CONFIG_CACHE_REDIS_PERSISTENT : true ),
					'dbid'                    =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_DBID' ) ?
							W3TC_CONFIG_CACHE_REDIS_DBID : 0 ),
					'password'                =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_PASSWORD' ) ?
							W3TC_CONFIG_CACHE_REDIS_PASSWORD : '' ),
					'timeout'                 =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_TIMEOUT' ) ?
							W3TC_CONFIG_CACHE_REDIS_TIMEOUT : 0 ),
					'retry_interval'          =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_RETRY_INTERVAL' ) ?
							W3TC_CONFIG_CACHE_REDIS_RETRY_INTERVAL : 0 ),
					'read_timeout'            =>
						( defined( 'W3TC_CONFIG_CACHE_REDIS_READ_TIMEOUT' ) ?
							W3TC_CONFIG_CACHE_REDIS_READ_TIMEOUT : 0 ),
					'key_version_mode'        => 'disabled',
				);
				break;
			default:
				$engine_config = array();
		}

		$engine_config['blog_id']     = '0';
		$engine_config['module']      = 'config';
		$engine_config['host']        = '';
		$engine_config['instance_id'] = ( defined( 'W3TC_INSTANCE_ID' ) ? W3TC_INSTANCE_ID : 0 );

		$cache = Cache::instance( W3TC_CONFIG_CACHE_ENGINE, $engine_config );

		return $cache;
	}

	/**
	 * Retrieves config cache key.
	 *
	 * @param int  $blog_id Blog ID.
	 * @param bool $preview Preview flag.
	 *
	 * @return string
	 */
	private static function get_key( $blog_id, $preview ) {
		return 'w3tc_config_' . $blog_id . ( $preview ? '_preview' : '' );
	}
}
