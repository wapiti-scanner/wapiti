<?php
namespace W3TC;

/**
 * PECL Memcached class
 */
class Cache_Nginx_Memcached extends Cache_Base {
	/**
	 * Memcache object
	 */
	private $_memcache = null;

	/*
	 * Configuration used to reinitialize persistent object
	 */
	private $_config = null;

	/**
	 * constructor
	 */
	function __construct( $config ) {
		parent::__construct( $config );

		if ( isset( $config['persistent'] ) && $config['persistent'] ) {
			$this->_config = $config;
			$this->_memcache = new \Memcached( $this->_get_key_version_key( '' ) );
			$server_list = $this->_memcache->getServerList();

			if ( empty( $server_list ) )
				return $this->initialize( $config );
			else
				return true;
		} else {
			$this->_memcache = new \Memcached();
			return $this->initialize( $config );
		}
	}

	/**
	 * Initializes
	 */
	private function initialize( $config ) {
		if ( empty( $config['servers'] ) )
			return false;

		if ( defined( '\Memcached::OPT_REMOVE_FAILED_SERVERS' ) ) {
			$this->_memcache->setOption( \Memcached::OPT_REMOVE_FAILED_SERVERS, true );
		}

		$this->_memcache->setOption( \Memcached::OPT_COMPRESSION, false );

		if ( isset( $config['aws_autodiscovery'] ) &&
			$config['aws_autodiscovery'] &&
			defined( '\Memcached::OPT_CLIENT_MODE' ) &&
			defined( '\Memcached::DYNAMIC_CLIENT_MODE' ) )
			$this->_memcache->setOption( \Memcached::OPT_CLIENT_MODE,
				\Memcached::DYNAMIC_CLIENT_MODE );

		foreach ( (array)$config['servers'] as $server ) {
			list( $ip, $port ) = Util_Content::endpoint_to_host_port( $server );
			$this->_memcache->addServer( $ip, $port );
		}

		if ( isset( $config['username'] ) && !empty( $config['username'] ) &&
			method_exists( $this->_memcache, 'setSaslAuthData' ) ) {
			$this->_memcache->setSaslAuthData( $config['username'],
				$config['password'] );
		}

		return true;
	}

	/**
	 * Adds data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function add( $key, &$var, $expire = 0, $group = '' ) {
		return $this->set( $key, $var, $expire, $group );
	}

	/**
	 * Sets data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function set( $key, $var, $expire = 0, $group = '' ) {
		$this->_memcache->setOption( \Memcached::OPT_USER_FLAGS,
			( isset( $var['c'] ) ? 1 : 0 ) );

		return @$this->_memcache->set( $key, $var['content'], $expire );
	}

	/**
	 * Returns data
	 *
	 * @param string  $key
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return mixed
	 */
	function get_with_old( $key, $group = '' ) {
		$has_old_data = false;

		$v = @$this->_memcache->get( $key );
		if ( $v === FALSE ) {
			return null;
		}

		$data = array( 'content' => $v );
		$data['compression'] = ( substr( $key, -5 ) == '_gzip' ? 'gzip' : '' );
		return array( $data, false );
	}

	/**
	 * Replaces data
	 *
	 * @param string  $key
	 * @param mixed   $var
	 * @param integer $expire
	 * @param string  $group  Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function replace( $key, &$var, $expire = 0, $group = '' ) {
		return $this->set( $key, $var, $expire, $group );
	}

	/**
	 * Deletes data
	 *
	 * @param string  $key
	 * @param string  $group
	 * @return boolean
	 */
	function delete( $key, $group = '' ) {
		return @$this->_memcache->delete( $key );
	}

	/**
	 * Key to delete, deletes _old and primary if exists.
	 *
	 * @param unknown $key
	 * @return bool
	 */
	function hard_delete( $key, $group = '' ) {
		return @$this->_memcache->delete( $key );
	}

	/**
	 * Flushes all data
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function flush( $group = '' ) {
		// can only flush everything from memcached, no way to flush only
		// pgcache cache
		return @$this->_memcache->flush();
	}

	/**
	 * Checks if engine can function properly in this environment
	 *
	 * @return bool
	 */
	public function available() {
		return class_exists( 'Memcached' );
	}

	public function get_statistics() {
		$a = $this->_memcache->getStats();
		if ( count( $a ) > 0 ) {
			$keys = array_keys( $a );
			$key = $keys[0];
			return $a[$key];
		}

		return $a;
	}

	/**
	 * Returns size used by cache
	 */
	public function get_stats_size( $timeout_time ) {
		$size = array(
			'bytes' => 0,
			'items' => 0,
			'timeout_occurred' => false,
		);

		$key_prefix = $this->get_item_key( '' );
		$error_occurred = false;

		$server_list = $this->_memcache->getServerList();
		$n = 0;

		foreach ( $server_list as $server ) {
			$loader = new Cache_Memcached_Stats( $server['host'], $server['port'] );
			$slabs = $loader->slabs();
			if ( !is_array( $slabs ) ) {
				$error_occurred = true;
				continue;
			}

			foreach ( $slabs as $slab_id ) {
				$cdump = $loader->cachedump( $slab_id );
				if ( !is_array( $cdump ) )
					continue;

				foreach ( $cdump as $line ) {
					$key_data = explode( ' ', $line );
					if ( !is_array( $key_data ) || count( $key_data ) < 3 )
						continue;
					$n++;
					if ( $n % 10 == 0 ) {
						$size['timeout_occurred'] = ( time() > $timeout_time );
						if ( $size['timeout_occurred'] )
							return $size;
					}

					$key = $key_data[1];
					$bytes = substr( $key_data[2], 1 );

					if ( substr( $key, 0, strlen( $key_prefix ) ) == $key_prefix ) {
						$size['bytes'] += $bytes;
						$size['items']++;
					}
				}
			}
		}

		if ( $error_occurred && $size['items'] <= 0 ) {
			$size['bytes'] = null;
			$size['items'] = null;
		}

		return $size;
	}

	/**
	 * Used to replace as atomically as possible known value to new one
	 */
	public function set_if_maybe_equals( $key, $old_value, $new_value ) {
		$storage_key = $this->get_item_key( $key );

		$cas = null;
		$value = @$this->_memcache->get( $storage_key, null, $cas );

		if ( !is_array( $value ) )
			return false;

		if ( isset( $old_value['content'] ) &&
			$value['content'] != $old_value['content'] )
			return false;

		return @$this->_memcache->cas( $cas, $storage_key, $new_value );
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_add( $key, $value ) {
		if ( $value == 0 )
			return true;

		$storage_key = $this->get_item_key( $key );
		$r = @$this->_memcache->increment( $storage_key, $value );
		if ( !$r )   // it doesnt initialize counter by itself
			$this->counter_set( $key, 0 );

		return $r;
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_set( $key, $value ) {
		$storage_key = $this->get_item_key( $key );
		return @$this->_memcache->set( $storage_key, $value );
	}

	/**
	 * Get counter's value
	 */
	public function counter_get( $key ) {
		$storage_key = $this->get_item_key( $key );
		$v = (int)@$this->_memcache->get( $storage_key );

		return $v;
	}

	public function get_item_key( $name ) {
		// memcached doesn't survive spaces in a key
		$key = sprintf( 'w3tc_%d_%s_%d_%s_%s',
			$this->_instance_id, $this->_host, $this->_blog_id,
			$this->_module, md5( $name ) );
		return $key;
	}
}
