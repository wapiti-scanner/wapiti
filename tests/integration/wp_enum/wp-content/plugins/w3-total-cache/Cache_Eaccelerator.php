<?php
namespace W3TC;

/**
 * eAccelerator class
 */
class Cache_Eaccelerator extends Cache_Base {

	/*
     * Used for faster flushing
     *
     * @var integer $_key_postfix
     */
	private $_key_version = array();

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
		if ( $this->get( $key, $group ) === false ) {
			return $this->set( $key, $var, $expire, $group );
		}

		return false;
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
		return eaccelerator_put( $storage_key, serialize( $var ), $expire );
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

		$v = @unserialize( eaccelerator_get( $storage_key ) );
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
			eaccelerator_put( $storage_key, serialize( $v ), 0 );
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
		if ( $this->get( $key, $group ) !== false ) {
			return $this->set( $key, $var, $expire, $group );
		}

		return false;
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
			$v = @unserialize( eaccelerator_get( $storage_key ) );
			if ( is_array( $v ) ) {
				$v['key_version'] = 0;
				eaccelerator_put( $storage_key, serialize( $v ), 0 );
				return true;
			}
		}

		return eaccelerator_rm( $key . '_' . $this->_blog_id );
	}


	/**
	 * Deletes _old and primary if exists.
	 *
	 * @param unknown $key
	 * @return bool
	 */
	function hard_delete( $key, $group = '' ) {
		$storage_key = $this->get_item_key( $key );
		return eaccelerator_rm( $storage_key );
	}
	/**
	 * Flushes all data
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return boolean
	 */
	function flush( $group = '' ) {
		$this->_get_key_version( $group );   // initialize $this->_key_version
		$this->_key_version[$group]++;
		$this->_set_key_version( $this->_key_version[$group], $group );

		return true;
	}

	/**
	 * Checks if engine can function properly in this environment
	 *
	 * @return bool
	 */
	public function available() {
		return function_exists( 'eaccelerator_put' );
	}

	/**
	 * Returns key postfix
	 *
	 * @param string  $group Used to differentiate between groups of cache values
	 * @return integer
	 */
	private function _get_key_version( $group = '' ) {
		if ( !isset( $this->_key_version[$group] ) || $this->_key_version[$group] <= 0 ) {
			$v = eaccelerator_get( $this->_get_key_version_key( $group ) );
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
		// cant guarantee atomic action here, filelocks fail often
		$value = $this->get( $key );
		if ( isset( $old_value['content'] ) &&
			$value['content'] != $old_value['content'] )
			return false;

		return $this->set( $key, $new_value );
	}

	/**
	 * Used to replace as atomically as possible known value to new one
	 */
	public function set_if_maybe_equals( $key, $old_value, $new_value ) {
		// eaccelerator cache not supported anymore by its authors
		return false;
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_add( $key, $value ) {
		// eaccelerator cache not supported anymore by its authors
		return false;
	}

	/**
	 * Use key as a counter and add integet value to it
	 */
	public function counter_set( $key, $value ) {
		// eaccelerator cache not supported anymore by its authors
		return false;
	}

	/**
	 * Get counter's value
	 */
	public function counter_get( $key ) {
		// eaccelerator cache not supported anymore by its authors
		return false;
	}
}
