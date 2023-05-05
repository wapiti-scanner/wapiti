<?php
namespace W3TC;

/**
 * component of shared code used by dbcache
 */
class DbCache_Core {
	public function get_usage_statistics_cache_config() {
		$c = Dispatcher::config();
		$engine = $c->get_string( 'dbcache.engine' );

		switch ( $engine ) {
		case 'memcached':
			$engineConfig = array(
				'servers' => $c->get_array( 'dbcache.memcached.servers' ),
				'persistent' => $c->get_boolean( 'dbcache.memcached.persistent' ),
				'aws_autodiscovery' => $c->get_boolean( 'dbcache.memcached.aws_autodiscovery' ),
				'username' => $c->get_string( 'dbcache.memcached.username' ),
				'password' => $c->get_string( 'dbcache.memcached.password' ),
				'binary_protocol' => $c->get_boolean( 'dbcache.memcached.binary_protocol' )
			);
			break;

		case 'redis':
			$engineConfig = array(
				'servers' => $c->get_array( 'dbcache.redis.servers' ),
				'verify_tls_certificates' => $c->get_boolean( 'dbcache.redis.verify_tls_certificates' ),
				'persistent' => $c->get_boolean( 'dbcache.redis.persistent' ),
				'timeout' => $c->get_integer( 'dbcache.redis.timeout' ),
				'retry_interval' => $c->get_integer( 'dbcache.redis.retry_interval' ),
				'read_timeout' => $c->get_integer( 'dbcache.redis.read_timeout' ),
				'dbid' => $c->get_integer( 'dbcache.redis.dbid' ),
				'password' => $c->get_string( 'dbcache.redis.password' )
			);
			break;

		default:
			$engineConfig = array();
		}

		$engineConfig['engine'] = $engine;
		return $engineConfig;
	}
}
