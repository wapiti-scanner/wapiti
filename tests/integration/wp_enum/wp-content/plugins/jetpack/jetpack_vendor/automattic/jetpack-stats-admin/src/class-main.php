<?php
/**
 * Stats Main
 *
 * @package automattic/jetpack-stats-admin
 */

namespace Automattic\Jetpack\Stats_Admin;

use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Stats\Options as Stats_Options;
use Automattic\Jetpack\Tracking;

/**
 * Stats Main class.
 *
 * Entrypoint for Stats.
 *
 * @since 0.1.0
 */
class Main {
	/**
	 * Stats version.
	 */
	const VERSION = '0.7.3';

	/**
	 * Singleton Main instance.
	 *
	 * @var Main
	 **/
	private static $instance = null;

	/**
	 * Initializer.
	 * Used to configure the stats package, eg when called via the Config package.
	 *
	 * @return object
	 */
	public static function init() {
		if ( null === self::$instance ) {
			self::$instance = new Main();
		}

		return self::$instance;
	}

	/**
	 * Class constructor.
	 *
	 * @return void
	 */
	private function __construct() {
		add_action( 'rest_api_init', array( new REST_Controller(), 'register_rest_routes' ) );
	}

	/**
	 * Update New Stats status.
	 *
	 * @param bool $status true to enable or false to disable.
	 * @return bool
	 */
	public static function update_new_stats_status( $status ) {
		$status = (bool) $status;

		$stats_options = array(
			'enable_odyssey_stats'     => $status,
			'odyssey_stats_changed_at' => time(),
		);
		$updated       = Stats_Options::set_options( $stats_options );

		// Track the event.
		$event_name = 'calypso_stats_disabled';
		if ( $status ) {
			$event_name = 'calypso_stats_enabled';
		}
		$connection_manager = new Manager( 'jetpack' );
		$tracking           = new Tracking( 'jetpack', $connection_manager );
		$tracking->record_user_event( $event_name, array_merge( $stats_options, array( 'updated' => $updated ) ) );

		return $updated;
	}
}
