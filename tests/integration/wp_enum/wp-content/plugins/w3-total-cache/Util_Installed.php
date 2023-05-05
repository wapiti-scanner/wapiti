<?php
namespace W3TC;

/**
 * Checks if different server modules are enabled and installed
 */
class Util_Installed {
	static public function opcache() {
		return function_exists( 'opcache_reset' ) && ini_get( 'opcache.enable' );
	}

	static public function apc() {
		return function_exists( 'apc_store' ) || function_exists( 'apcu_store' );
	}

	static public function apc_opcache() {
		return function_exists( 'apc_compile_file' ) && ini_get( 'apc.enable' );
	}

	public static function is_opcache_validate_timestamps() {
		return  ini_get( 'opcache.validate_timestamps' );
	}

	public static function is_apc_validate_timestamps() {
		return ini_get( 'apc.stat' );
	}

	static public function curl() {
		return function_exists( 'curl_init' );
	}



	static public function eaccelerator() {
		return function_exists( 'eaccelerator_put' );
	}



	static public function ftp() {
		return function_exists( 'ftp_connect' );
	}



	static public function memcached_auth() {
		static $r = null;
		if ( is_null( $r ) ) {
			if ( !class_exists( '\Memcached' ) )
				$r = false;
			else {
				$o = new \Memcached();
				$r = method_exists( $o, 'setSaslAuthData' );
			}
		}

		return $r;
	}



	static public function memcached() {
		return class_exists( 'Memcache' ) || class_exists( 'Memcached' );
	}



	static public function memcached_memcached() {
		return class_exists( 'Memcached' );
	}



	static public function memcached_aws() {
		return class_exists( '\Memcached' ) &&
			defined( '\Memcached::OPT_CLIENT_MODE' ) &&
			defined( '\Memcached::DYNAMIC_CLIENT_MODE' );
	}



	static function memcache_auth() {
		static $r = null;
		if ( is_null( $r ) ) {
			if ( !class_exists( '\Memcached' ) )
				$r = false;
			else {
				$o = new \Memcached();
				$r = method_exists( $o, 'setSaslAuthData' );
			}
		}

		return $r;
	}



	static public function redis() {
		return class_exists( 'Redis' );
	}



	static public function tidy() {
		return class_exists( 'tidy' );
	}



	static public function wincache() {
		return function_exists( 'wincache_ucache_set' );
	}



	static public function xcache() {
		return function_exists( 'xcache_set' );
	}



	/**
	 * Check if memcache is available
	 *
	 * @param array   $servers
	 * @return boolean
	 */
	static public function is_memcache_available( $servers ) {
		static $results = array();

		$key = md5( implode( '', $servers ) );

		if ( !isset( $results[$key] ) ) {
			$memcached = Cache::instance( 'memcached', array(
					'servers' => $servers,
					'persistent' => false
				) );
			if ( is_null( $memcached ) )
				return false;

			$test_string = sprintf( 'test_' . md5( time() ) );
			$test_value = array( 'content' => $test_string );
			$memcached->set( $test_string, $test_value, 60 );
			$test_value = $memcached->get( $test_string );
			$results[$key] = ( $test_value['content'] == $test_string );
		}

		return $results[$key];
	}
}
