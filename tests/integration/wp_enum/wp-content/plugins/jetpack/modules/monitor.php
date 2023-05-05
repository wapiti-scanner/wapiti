<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Monitor
 * Module Description: Jetpack’s downtime monitoring will continuously watch your site and alert you the moment that downtime is detected.
 * Sort Order: 28
 * Recommendation Order: 10
 * First Introduced: 2.6
 * Requires Connection: Yes
 * Requires User Connection: Yes
 * Auto Activate: No
 * Module Tags: Recommended
 * Feature: Security
 * Additional Search Queries: monitor, uptime, downtime, monitoring, maintenance, maintenance mode, offline, site is down, site down, down, repair, error
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Manager as Connection_Manager;

/**
 * Class Jetpack_Monitor
 */
class Jetpack_Monitor {

	/**
	 * Name of the module.
	 *
	 * @var string Name of module.
	 */
	public $module = 'monitor';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'jetpack_modules_loaded', array( $this, 'jetpack_modules_loaded' ) );
		add_action( 'jetpack_activate_module_monitor', array( $this, 'activate_module' ) );
	}

	/**
	 * Runs upon module activation.
	 *
	 * @return void
	 */
	public function activate_module() {
		if ( ( new Connection_Manager( 'jetpack' ) )->is_user_connected() ) {
			self::update_option_receive_jetpack_monitor_notification( true );
		}
	}

	/**
	 * Runs on the jetpack_modules_loaded hook to enable configuation.
	 *
	 * @return void
	 */
	public function jetpack_modules_loaded() {
		Jetpack::enable_module_configurable( $this->module );
	}

	/**
	 * Whether to receive the notifications.
	 *
	 * @param bool $value `true` to enable notifications, `false` to disable them.
	 *
	 * @return bool
	 */
	public function update_option_receive_jetpack_monitor_notification( $value ) {
		$xml = new Jetpack_IXR_Client(
			array(
				'user_id' => get_current_user_id(),
			)
		);
		$xml->query( 'jetpack.monitor.setNotifications', (bool) $value );

		if ( $xml->isError() ) {
			wp_die( sprintf( '%s: %s', esc_html( $xml->getErrorCode() ), esc_html( $xml->getErrorMessage() ) ) );
		}

		// To be used only in Jetpack_Core_Json_Api_Endpoints::get_remote_value.
		update_option( 'monitor_receive_notifications', (bool) $value );

		return true;
	}

	/**
	 * Checks the status of notifications for current Jetpack site user.
	 *
	 * @since 2.8
	 * @since 4.1.0 New parameter $die_on_error.
	 *
	 * @param bool $die_on_error Whether to issue a wp_die when an error occurs or return a WP_Error object.
	 *
	 * @return boolean|WP_Error
	 */
	public static function user_receives_notifications( $die_on_error = true ) {
		$xml = new Jetpack_IXR_Client(
			array(
				'user_id' => get_current_user_id(),
			)
		);
		$xml->query( 'jetpack.monitor.isUserInNotifications' );

		if ( $xml->isError() ) {
			if ( $die_on_error ) {
				wp_die( sprintf( '%s: %s', esc_html( $xml->getErrorCode() ), esc_html( $xml->getErrorMessage() ) ), 400 );
			} else {
				return new WP_Error( $xml->getErrorCode(), $xml->getErrorMessage(), array( 'status' => 400 ) );
			}
		}
		return $xml->getResponse();
	}

	/**
	 * Returns date of the last downtime.
	 *
	 * @since 4.0.0
	 * @return string date in YYYY-MM-DD HH:mm:ss format
	 */
	public function monitor_get_last_downtime() {
		$xml = new Jetpack_IXR_Client();

		$xml->query( 'jetpack.monitor.getLastDowntime' );

		if ( $xml->isError() ) {
			return new WP_Error( 'monitor-downtime', $xml->getErrorMessage() );
		}

		set_transient( 'monitor_last_downtime', $xml->getResponse(), 10 * MINUTE_IN_SECONDS );

		return $xml->getResponse();
	}

}

new Jetpack_Monitor();
