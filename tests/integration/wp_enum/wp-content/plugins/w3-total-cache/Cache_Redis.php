<?php
/**
 * File: Cache_Redis.php
 *
 * @package W3TC
 *
 * phpcs:disable PSR2.Methods.MethodDeclaration.Underscore,PSR2.Classes.PropertyDeclaration.Underscore,WordPress.PHP.DiscouragedPHPFunctions,WordPress.PHP.NoSilencedErrors
 */

namespace W3TC;

/**
 * Redis cache engine.
 */
class Cache_Redis extends Cache_Base {
	/**
	 * Accessors.
	 *
	 * @var array
	 */
	private $_accessors = array();

	/**
	 * Key value.
	 *
	 * @var array
	 */
	private $_key_version = array();

	/**
	 * Persistent.
	 *
	 * @var bool
	 */
	private $_persistent;

	/**
	 * Password.
	 *
	 * @var string
	 */
	private $_password;

	/**
	 * Servers.
	 *
	 * @var array
	 */
	private $_servers;

	/**
	 * Verify TLS certificate.
	 *
	 * @var bool
	 */
	private $_verify_tls_certificates;

	/**
	 * DB id.
	 *
	 * @var string
	 */
	private $_dbid;

	/**
	 * Timeout.
	 *
	 * @var int.
	 */
	private $_timeout;

	/**
	 * Retry interval.
	 *
	 * @var int
	 */
	private $_retry_interval;

	/**
	 * Retry timeout.
	 *
	 * @var int
	 */
	private $_read_timeout;

	/**
	 * Constructor.
	 *
	 * @param array $config Config.
	 */
	public function __construct( $config ) {
		parent::__construct( $config );

		$this->_persistent              = ( isset( $config['persistent'] ) && $config['persistent'] );
		$this->_servers                 = (array) $config['servers'];
		$this->_verify_tls_certificates = ( isset( $config['verify_tls_certificates'] ) && $config['verify_tls_certificates'] );
		$this->_password                = $config['password'];
		$this->_dbid                    = $config['dbid'];
		$this->_timeout                 = $config['timeout'];
		$this->_retry_interval          = $config['retry_interval'];
		$this->_read_timeout            = $config['read_timeout'];

		/**
		 * When disabled - no extra requests are made to obtain key version,
		 * but flush operations not supported as a result group should be always empty.
		 */
		if ( isset( $config['key_version_mode'] ) && 'disabled' === $config['key_version_mode'] ) {
			$this->_key_version[''] = 1;
		}
	}

	/**
	 * Adds data.
	 *
	 * @param string  $key    Key.
	 * @param mixed   $var    Var.
	 * @param integer $expire Expire.
	 * @param string  $group  Used to differentiate between groups of cache values.
	 * @return bool
	 */
	public function add( $key, &$var, $expire = 0, $group = '' ) {
		return $this->set( $key, $var, $expire, $group );
	}

	/**
	 * Sets data.
	 *
	 * @param string  $key    Key.
	 * @param mixed   $value  Value.
	 * @param integer $expire Expire.
	 * @param string  $group  Used to differentiate between groups of cache values.
	 * @return bool
	 */
	public function set( $key, $value, $expire = 0, $group = '' ) {
		$value['key_version'] = $this->_get_key_version( $group );

		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		if ( ! $expire ) {
			return $accessor->set( $storage_key, serialize( $value ) );
		}

		return $accessor->setex( $storage_key, $expire, serialize( $value ) );
	}

	/**
	 * Returns data
	 *
	 * @param string $key   Key.
	 * @param string $group Used to differentiate between groups of cache values.
	 * @return mixed
	 */
	public function get_with_old( $key, $group = '' ) {
		$has_old_data = false;

		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return array( null, false );
		}

		$v = $accessor->get( $storage_key );
		$v = @unserialize( $v );

		if ( ! is_array( $v ) || ! isset( $v['key_version'] ) ) {
			return array( null, $has_old_data );
		}

		$key_version = $this->_get_key_version( $group );
		if ( $v['key_version'] === $key_version ) {
			return array( $v, $has_old_data );
		}

		if ( $v['key_version'] > $key_version ) {
			$this->_set_key_version( $v['key_version'], $group );
			return array( $v, $has_old_data );
		}

		// Key version is old.
		if ( ! $this->_use_expired_data ) {
			return array( null, $has_old_data );
		}

		// If we have expired data - update it for future use and let current process recalculate it.
		$expires_at = isset( $v['expires_at'] ) ? $v['expires_at'] : null;

		if ( is_null( $expires_at ) || time() > $expires_at ) {
			$v['expires_at'] = time() + 30;
			$accessor->setex( $storage_key, 60, serialize( $v ) );
			$has_old_data = true;

			return array( null, $has_old_data );
		}

		// Return old version.
		return array( $v, $has_old_data );
	}

	/**
	 * Replaces data.
	 *
	 * @param string  $key    Key.
	 * @param mixed   $value  Value.
	 * @param integer $expire Expire.
	 * @param string  $group  Used to differentiate between groups of cache values.
	 * @return bool
	 */
	public function replace( $key, &$value, $expire = 0, $group = '' ) {
		return $this->set( $key, $value, $expire, $group );
	}

	/**
	 * Deletes data.
	 *
	 * @param string $key   Key.
	 * @param string $group Group.
	 * @return bool
	 */
	public function delete( $key, $group = '' ) {
		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		if ( $this->_use_expired_data ) {
			$v   = $accessor->get( $storage_key );
			$ttl = $accessor->ttl( $storage_key );

			if ( is_array( $v ) ) {
				$v['key_version'] = 0;
				$accessor->setex( $storage_key, $ttl, $v );
				return true;
			}
		}

		return $accessor->setex( $storage_key, 1, '' );
	}

	/**
	 * Key to delete, deletes _old and primary if exists.
	 *
	 * @param string $key   Key.
	 * @param string $group Group.
	 * @return bool
	 */
	public function hard_delete( $key, $group = '' ) {
		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		return $accessor->setex( $storage_key, 1, '' );
	}

	/**
	 * Flushes all data.
	 *
	 * @param string $group Used to differentiate between groups of cache values.
	 * @return bool
	 */
	public function flush( $group = '' ) {
		$this->_get_key_version( $group );   // Initialize $this->_key_version.
		if ( isset( $this->_key_version[ $group ] ) ) {
			$this->_key_version[ $group ]++;
			$this->_set_key_version( $this->_key_version[ $group ], $group );
		}

		return true;
	}

	/**
	 * Checks if engine can function properly in this environment.
	 *
	 * @return bool
	 */
	public function available() {
		return class_exists( 'Redis' );
	}

	/**
	 * Get statistics.
	 *
	 * @return array
	 */
	public function get_statistics() {
		$accessor = $this->_get_accessor( '' ); // Single-server mode used for stats.

		if ( is_null( $accessor ) ) {
			return array();
		}

		$a = $accessor->info();

		return $a;
	}

	/**
	 * Returns key version.
	 *
	 * @param string $group Used to differentiate between groups of cache values.
	 * @return int
	 */
	private function _get_key_version( $group = '' ) {
		if ( ! isset( $this->_key_version[ $group ] ) || $this->_key_version[ $group ] <= 0 ) {
			$storage_key = $this->_get_key_version_key( $group );
			$accessor    = $this->_get_accessor( $storage_key );

			if ( is_null( $accessor ) ) {
				return 0;
			}

			$v_original = $accessor->get( $storage_key );
			$v          = intval( $v_original );
			$v          = ( $v > 0 ? $v : 1 );

			if ( (string) $v_original !== (string) $v ) {
				$accessor->set( $storage_key, $v );
			}

			$this->_key_version[ $group ] = $v;
		}

		return $this->_key_version[ $group ];
	}

	/**
	 * Sets new key version.
	 *
	 * @param string $v     Version.
	 * @param string $group Used to differentiate between groups of cache values.
	 * @return bool
	 */
	private function _set_key_version( $v, $group = '' ) {
		$storage_key = $this->_get_key_version_key( $group );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		$accessor->set( $storage_key, $v );

		return true;
	}

	/**
	 * Used to replace as atomically as possible known value to new one.
	 *
	 * @param string $key       Key.
	 * @param string $old_value Old value.
	 * @param string $new_value New value.
	 */
	public function set_if_maybe_equals( $key, $old_value, $new_value ) {
		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		$accessor->watch( $storage_key );

		$value = $accessor->get( $storage_key );
		$value = @unserialize( $value );

		if ( ! is_array( $value ) ) {
			$accessor->unwatch();
			return false;
		}

		if ( isset( $old_value['content'] ) && $value['content'] !== $old_value['content'] ) {
			$accessor->unwatch();
			return false;
		}

		return $accessor->multi()
			->set( $storage_key, $new_value )
			->exec();
	}

	/**
	 * Use key as a counter and add integet value to it.
	 *
	 * @param string $key   Key.
	 * @param int    $value Value.
	 */
	public function counter_add( $key, $value ) {
		if ( empty( $value ) ) {
			return true;
		}

		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		$r = $accessor->incrBy( $storage_key, $value );

		if ( ! $r ) { // It doesn't initialize counter by itself.
			$this->counter_set( $key, 0 );
		}

		return $r;
	}

	/**
	 * Use key as a counter and add integet value to it.
	 *
	 * @param string $key   Key.
	 * @param int    $value Value.
	 */
	public function counter_set( $key, $value ) {
		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return false;
		}

		return $accessor->set( $storage_key, $value );
	}

	/**
	 * Get counter's value.
	 *
	 * @param string $key Key.
	 */
	public function counter_get( $key ) {
		$storage_key = $this->get_item_key( $key );
		$accessor    = $this->_get_accessor( $storage_key );

		if ( is_null( $accessor ) ) {
			return 0;
		}

		$v = (int) $accessor->get( $storage_key );

		return $v;
	}

	/**
	 * Build Redis connection arguments based on server URI
	 *
	 * @param string $server Server URI to connect to.
	 */
	private function build_connect_args( $server ) {
		$connect_args = array();

		if ( substr( $server, 0, 5 ) === 'unix:' ) {
			$connect_args[] = trim( substr( $server, 5 ) );
			$connect_args[] = null; // port.
		} else {
			list( $ip, $port ) = Util_Content::endpoint_to_host_port( $server, null );
			$connect_args[]    = $ip;
			$connect_args[]    = $port;
		}

		$connect_args[] = $this->_timeout;
		$connect_args[] = $this->_persistent ? $this->_instance_id . '_' . $this->_dbid : null;
		$connect_args[] = $this->_retry_interval;

		$phpredis_version = phpversion( 'redis' );

		// The read_timeout parameter was added in phpredis 3.1.3.
		if ( version_compare( $phpredis_version, '3.1.3', '>=' ) ) {
			$connect_args[] = $this->_read_timeout;
		}

		// Support for stream context was added in phpredis 5.3.2.
		if ( version_compare( $phpredis_version, '5.3.2', '>=' ) ) {
			$context = array();
			if ( 'tls:' === substr( $server, 0, 4 ) && ! $this->_verify_tls_certificates ) {
				$context['stream'] = array(
					'verify_peer'      => false,
					'verify_peer_name' => false,
				);
			}
			$connect_args[] = $context;
		}

		return $connect_args;
	}

	/**
	 * Get accessor.
	 *
	 * @param string $key Key.
	 * @return object
	 */
	private function _get_accessor( $key ) {
		if ( count( $this->_servers ) <= 1 ) {
			$index = 0;
		} else {
			$index = crc32( $key ) % count( $this->_servers );
		}

		if ( isset( $this->_accessors[ $index ] ) ) {
			return $this->_accessors[ $index ];
		}

		if ( ! isset( $this->_servers[ $index ] ) ) {
			$this->_accessors[ $index ] = null;
		} else {
			try {
				$server       = $this->_servers[ $index ];
				$connect_args = $this->build_connect_args( $server );

				$accessor = new \Redis();

				if ( $this->_persistent ) {
					$accessor->pconnect( ...$connect_args );
				} else {
					$accessor->connect( ...$connect_args );
				}

				if ( ! empty( $this->_password ) ) {
					$accessor->auth( $this->_password );
				}

				$accessor->select( $this->_dbid );
			} catch ( \Exception $e ) {
				error_log( $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				$accessor = null;
			}

			$this->_accessors[ $index ] = $accessor;
		}

		return $this->_accessors[ $index ];
	}
}
