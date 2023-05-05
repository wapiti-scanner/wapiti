<?php
/**
 * Stats sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Heartbeat;

/**
 * Class to handle sync for stats.
 */
class Stats extends Module {
	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'stats';
	}

	/**
	 * Initialize stats action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callback Action handler callable.
	 */
	public function init_listeners( $callback ) {
		add_action( 'jetpack_heartbeat', array( $this, 'sync_site_stats' ), 20 );
		add_action( 'jetpack_sync_heartbeat_stats', $callback );
	}

	/**
	 * This namespaces the action that we sync.
	 * So that we can differentiate it from future actions.
	 *
	 * @access public
	 */
	public function sync_site_stats() {
		do_action( 'jetpack_sync_heartbeat_stats' );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		add_filter( 'jetpack_sync_before_send_jetpack_sync_heartbeat_stats', array( $this, 'add_stats' ) );
	}

	/**
	 * Retrieve the stats data for the site.
	 *
	 * @access public
	 *
	 * @return array Stats data.
	 */
	public function add_stats() {
		return array( Heartbeat::generate_stats_array() );
	}
}
