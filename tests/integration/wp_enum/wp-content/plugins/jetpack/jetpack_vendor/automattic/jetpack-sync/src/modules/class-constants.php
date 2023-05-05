<?php
/**
 * Constants sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Defaults;

/**
 * Class to handle sync for constants.
 */
class Constants extends Module {
	/**
	 * Name of the constants checksum option.
	 *
	 * @var string
	 */
	const CONSTANTS_CHECKSUM_OPTION_NAME = 'jetpack_constants_sync_checksum';

	/**
	 * Name of the transient for locking constants.
	 *
	 * @var string
	 */
	const CONSTANTS_AWAIT_TRANSIENT_NAME = 'jetpack_sync_constants_await';

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'constants';
	}

	/**
	 * Initialize constants action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'jetpack_sync_constant', $callable, 10, 2 );
	}

	/**
	 * Initialize constants action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_constants', $callable );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		add_action( 'jetpack_sync_before_send_queue_sync', array( $this, 'maybe_sync_constants' ) );

		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_constants', array( $this, 'expand_constants' ) );
	}

	/**
	 * Perform module cleanup.
	 * Deletes any transients and options that this module uses.
	 * Usually triggered when uninstalling the plugin.
	 *
	 * @access public
	 */
	public function reset_data() {
		delete_option( self::CONSTANTS_CHECKSUM_OPTION_NAME );
		delete_transient( self::CONSTANTS_AWAIT_TRANSIENT_NAME );
	}

	/**
	 * Set the constants whitelist.
	 *
	 * @access public
	 * @todo We don't seem to use this one. Should we remove it?
	 *
	 * @param array $constants The new constants whitelist.
	 */
	public function set_constants_whitelist( $constants ) {
		$this->constants_whitelist = $constants;
	}

	/**
	 * Get the constants whitelist.
	 *
	 * @access public
	 *
	 * @return array The constants whitelist.
	 */
	public function get_constants_whitelist() {
		return Defaults::get_constants_whitelist();
	}

	/**
	 * Enqueue the constants actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state True if full sync has finished enqueueing this module, false otherwise.
	 *
	 * @return array Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		/**
		 * Tells the client to sync all constants to the server
		 *
		 * @param boolean Whether to expand constants (should always be true)
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 */
		do_action( 'jetpack_full_sync_constants', true );

		// The number of actions enqueued, and next module state (true == done).
		return array( 1, true );
	}

	/**
	 * Send the constants actions for full sync.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @param int   $send_until The timestamp until the current request can send.
	 * @param array $state This module Full Sync status.
	 *
	 * @return array This module Full Sync status.
	 */
	public function send_full_sync_actions( $config, $send_until, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// we call this instead of do_action when sending immediately.
		$this->send_action( 'jetpack_full_sync_constants', array( true ) );

		// The number of actions enqueued, and next module state (true == done).
		return array( 'finished' => true );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 *
	 * @return array Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 1;
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_constants' );
	}

	/**
	 * Sync the constants if we're supposed to.
	 *
	 * @access public
	 */
	public function maybe_sync_constants() {
		if ( get_transient( self::CONSTANTS_AWAIT_TRANSIENT_NAME ) ) {
			return;
		}

		set_transient( self::CONSTANTS_AWAIT_TRANSIENT_NAME, microtime( true ), Defaults::$default_sync_constants_wait_time );

		$constants = $this->get_all_constants();
		if ( empty( $constants ) ) {
			return;
		}

		$constants_checksums = (array) get_option( self::CONSTANTS_CHECKSUM_OPTION_NAME, array() );

		foreach ( $constants as $name => $value ) {
			$checksum = $this->get_check_sum( $value );
			// Explicitly not using Identical comparison as get_option returns a string.
			if ( ! $this->still_valid_checksum( $constants_checksums, $name, $checksum ) && $value !== null ) {
				/**
				 * Tells the client to sync a constant to the server
				 *
				 * @param string The name of the constant
				 * @param mixed The value of the constant
				 *
				 * @since 1.6.3
				 * @since-jetpack 4.2.0
				 */
				do_action( 'jetpack_sync_constant', $name, $value );
				$constants_checksums[ $name ] = $checksum;
			} else {
				$constants_checksums[ $name ] = $checksum;
			}
		}
		update_option( self::CONSTANTS_CHECKSUM_OPTION_NAME, $constants_checksums );
	}

	/**
	 * Retrieve all constants as per the current constants whitelist.
	 * Public so that we don't have to store an option for each constant.
	 *
	 * @access public
	 *
	 * @return array All constants.
	 */
	public function get_all_constants() {
		$constants_whitelist = $this->get_constants_whitelist();

		return array_combine(
			$constants_whitelist,
			array_map( array( $this, 'get_constant' ), $constants_whitelist )
		);
	}

	/**
	 * Retrieve the value of a constant.
	 * Used as a wrapper to standartize access to constants.
	 *
	 * @access private
	 *
	 * @param string $constant Constant name.
	 *
	 * @return mixed Return value of the constant.
	 */
	private function get_constant( $constant ) {
		return ( defined( $constant ) ) ?
			constant( $constant )
			: null;
	}

	/**
	 * Expand the constants within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 *
	 * @return array $args The hook parameters.
	 */
	public function expand_constants( $args ) {
		if ( $args[0] ) {
			$constants           = $this->get_all_constants();
			$constants_checksums = array();
			foreach ( $constants as $name => $value ) {
				$constants_checksums[ $name ] = $this->get_check_sum( $value );
			}
			update_option( self::CONSTANTS_CHECKSUM_OPTION_NAME, $constants_checksums );

			return $constants;
		}

		return $args;
	}

	/**
	 * Return Total number of objects.
	 *
	 * @param array $config Full Sync config.
	 *
	 * @return int total
	 */
	public function total( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return count( $this->get_constants_whitelist() );
	}

	/**
	 * Retrieve a set of constants by their IDs.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids         Object IDs.
	 * @return array Array of objects.
	 */
	public function get_objects_by_id( $object_type, $ids ) {
		if ( empty( $ids ) || empty( $object_type ) || 'constant' !== $object_type ) {
			return array();
		}

		$objects = array();
		foreach ( (array) $ids as $id ) {
			$object = $this->get_object_by_id( $object_type, $id );

			if ( 'all' === $id ) {
				// If all was requested it contains all options and can simply be returned.
				return $object;
			}
			$objects[ $id ] = $object;
		}

		return $objects;
	}

	/**
	 * Retrieve a constant by its name.
	 *
	 * @access public
	 *
	 * @param string $object_type Type of the sync object.
	 * @param string $id          ID of the sync object.
	 * @return mixed              Value of Constant.
	 */
	public function get_object_by_id( $object_type, $id ) {
		if ( 'constant' === $object_type ) {

			// Only whitelisted constants can be returned.
			if ( in_array( $id, $this->get_constants_whitelist(), true ) ) {
				return $this->get_constant( $id );
			} elseif ( 'all' === $id ) {
				return $this->get_all_constants();
			}
		}

		return false;
	}

}
