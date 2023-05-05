<?php
namespace W3TC;

/**
 * Used to show notes at blog-level when master configs are changed
 *
 * keys - see ConfigState comment with a list of keys with "timestamp" word
 */
class ConfigStateNote {
	private $_config_state_master;
	private $_config_state;



	/**
	 * Constructor
	 */
	public function __construct( $config_state_master, $config_state ) {
		$this->_config_state_master = $config_state_master;
		$this->_config_state = $config_state;
	}

	/**
	 * Returns value
	 *
	 * @param string  $key
	 * @param string  $default
	 * @return mixed
	 */
	public function get( $key ) {
		$timestamp = $this->_config_state->get_integer( $key . '.timestamp' );
		$timestamp_master = $this->_config_state_master->get_integer(
			$key . '.timestamp' );

		if ( $timestamp > $timestamp_master )
			return $this->_config_state->get_boolean( $key );
		else
			return $this->_config_state_master->get_boolean( $key );
	}

	/**
	 * Sets flag to true/false
	 */
	public function set( $key, $value ) {
		$this->_config_state->set( $key, $value );
		$this->_config_state->set( $key . '.timestamp', time() );
		$this->_config_state->save();
	}
}
