<?php
namespace W3TC;

/**
 * PECL Memcache class
 */
class Cache_Memcache extends Cache_Base {
	/**
	 * Memcache object
	 *
	 * @var Memcache
	 */
	private $_memcache = null;

	/*
	 * Used for faster flushing
	 *
	 * @var integer $_key_version
	 */
	private $_key_version = array();

	/**
	 * constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config ) {
		parent::__construct( $config );

		$this->_memcache = new \Memcache();

		if ( !empty( $config['servers'] ) ) {
			$persistent = isset( $config['persistent'] ) ? (boolean) $config['persistent'] : false;

			foreach ( (array) $config['servers'] as $server ) {
				list( $ip, $port ) = Util_Content::endpoint_to_host_port( $server );
				$this->_memcache->addServer( $ip, $port, $persistent );
			}
		} else {
			return false;
		}

		// when disabled - no extra requests are made to obtain key version,
		// but flush operations not supported as a result
		// group should be always empty
		if ( isset( $config['key_version_mode'] ) &&
			$config['key_version_mode'] == 'disabled' ) {
			$this->_key_version[''] = 1;
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
		$var['key_version'] = $this->_get_key_version( $group );

		$storage_key = $this->get_item_key( $key );
		return @$this->_memcache->set( $storage_key, $var, false, $expire );
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

		$storage_key = $this->get_item_key( $key );

		$v = @$this->_memcache->get( $storage_key );
		if ( !is_array( $v ) || !isset( $v['key_version'] ) )
			return array( null, $has_old_data );

		$key_version = $this->_get_key_version( $group );
		if ( $v['key_version'] == $key_version )
			return array( $v, $has_old_data );

		if ( $v['key_version'] > $key_version ) {
			$this->_set_key_version( $v['key_version'], $group );
			return array( $v, $has_old_data );
		}

		// key version is old
		if ( !$this->_use_expired_data )
			return array( null, $has_old_data );

		// if we have expired data - update it for future use and let
		// current process recalculate it
		$expires_at = isset( $v['expires_at'] ) ? $v['expires_at'] : null;
		if ( $expires_at == null || time() > $expires_at ) {
			$v['expires_at'] = time() + 30;
			@$this->_memcache->set( $storage_key, $v, false, 0 );
			$has_old_data = true;

			return array( null, $has_old_data );
		}

		// return old version
		return array( $v, $has_old_data );
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
		$storage_key = $this->get_item_key( $key );

		if ( $this->_use_expired_data ) {
			$v = @$this->_memcache->get( $storage_key );
			if ( is_array( $v ) ) {
				$v['key_version'] = 0;
				@$this->_memcache->set( $storage_key, $v, false, 0 );
				return true;
			}
		}
		return @$this->_memcache->delete( $storage_key, 0 );
	}

	/**
	 * Key to delete, deletes _old and primary if exists.
	 *
	 * @param unknown $key
	 * @return bool
	 */
	function hard_delete( $key, $group = '' ) {
		$storage_key = $this->get_item_key( $key );
		return @$this->_memcache->delete( $storage_key, 0 );
	}

	/**
	 * Flushes all data
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function flush( $group = '' ) {
		$this->_increment_key_version( $group );
		return true;
	}

	/**
	 * Checks if engine can function properly in this environment
	 *
	 * @return bool
	 */
	public function available() {
		return class_exists( 'Memcache' );
	}

	public function get_statistics() {
		return $this->_memcache->getStats();
	}

	/**
	 * Returns key version
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return integer
	 */
	private function _get_key_version( $group = '' ) {
		if ( !isset( $this->_key_version[$group] ) || $this->_key_version[$group] <= 0 ) {
			$v = @$this->_memcache->get( $this->_get_key_version_key( $group ) );
			$v = intval( $v );
			$this->_key_version[$group] = ( $v > 0 ? $v : 1 );
		}

		return $this->_key_version[$group];
	}

	/**
	 * Sets new key version
	 *
	 * @param unknown $v
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	private function _set_key_version( $v, $group = '' ) {
		// expiration has to be as long as possible since
		// all cache data expires when key version expires
		@$this->_memcache->set( $this->_get_key_version_key( $group ), $v, false, 0 );
		$this->_key_version[$group] = $v;
	}

	/**
	 * Increments key version.
	 *
	 * @since 0.14.5
	 *
	 * @param string $group Used to differentiate between groups of cache values.
	 */
	private function _increment_key_version( $group = '' ) {
		$r = @$this->_memcache->increment( $this->_get_key_version_key( $group ), 1 );

		if ( $r ) {
			$this->_key_version[$group] = $r;
		} else {
			// it doesn't initialize the key if it doesn't exist.
			$this->_set_key_version( 2, $group );
		}
	}

	/**
	 * Returns size used by cache
	 */
	public function get_stats_size( $timeout_time ) {
		$size = array(
			'bytes' => 0,
			'items' => 0,
			'timeout_occurred' => false
		);

		$key_prefix = $this->get_item_key( '' );

		$slabs = @$this->_memcache->getExtendedStats( 'slabs' );
		$slabs_plain = array();

		if ( is_array( $slabs ) ) {
			foreach ( $slabs as $server => $server_slabs ) {
				foreach ( $server_slabs as $slab_id => $slab_meta ) {
					if ( (int)$slab_id > 0 )
						$slabs_plain[(int)$slab_id] = '*';
				}
			}
		}

		foreach ( $slabs_plain as $slab_id => $nothing ) {
			$cdump = @$this->_memcache->getExtendedStats( 'cachedump',
				(int)$slab_id );
			if ( !is_array( $cdump ) )
				continue;

			foreach ( $cdump as $server => $keys_data ) {
				if ( !is_array( $keys_data ) )
					continue;

				foreach ( $keys_data as $key => $size_expiration ) {
					if ( substr( $key, 0, strlen( $key_prefix ) ) == $key_prefix ) {
						if ( count( $size_expiration ) > 0 ) {
							$size['bytes'] += $size_expiration[0];
							$size['items']++;
						}
					}

				}
			}
		}

		return $size;
	}

	/**
	 * Used to replace as atomically as possible known value to new one
	 */
	public function set_if_maybe_equals( $key, $old_value, $new_value ) {
		// cant guarantee atomic action here, memcache doesnt support CAS
		$value = $this->get( $key );
		if ( isset( $old_value['content'] ) &&
			$value['content'] != $old_value['content'] )
			return false;

		return $this->set( $key, $new_value );
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
