<?php
/**
 * Protect sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Constants as Jetpack_Constants;
use Automattic\Jetpack\Waf\Brute_Force_Protection\Brute_Force_Protection;

/**
 * Class to handle sync for Protect.
 * Logs BruteProtect failed logins via sync.
 */
class Protect extends Module {
	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'protect';
	}

	/**
	 * Initialize Protect action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callback Action handler callable.
	 */
	public function init_listeners( $callback ) {
		add_action( 'jpp_log_failed_attempt', array( $this, 'maybe_log_failed_login_attempt' ) );
		add_action( 'jetpack_valid_failed_login_attempt', $callback );
	}

	/**
	 * Maybe log a failed login attempt.
	 *
	 * @access public
	 *
	 * @param array $failed_attempt Failed attempt data.
	 */
	public function maybe_log_failed_login_attempt( $failed_attempt ) {
		$brute_force_protection = Brute_Force_Protection::instance();
		if ( $brute_force_protection->has_login_ability() && ! Jetpack_Constants::is_true( 'XMLRPC_REQUEST' ) ) {
			do_action( 'jetpack_valid_failed_login_attempt', $failed_attempt );
		}
	}
}
