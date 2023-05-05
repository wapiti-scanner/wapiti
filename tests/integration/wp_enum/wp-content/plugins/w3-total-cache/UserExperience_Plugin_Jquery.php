<?php
/**
 * File: UserExperience_Plugin_Jquery.php
 *
 * @since 0.14.4
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: UserExperience_Plugin_Jquery
 *
 * @since 0.14.4
 */
class UserExperience_Plugin_Jquery {
	/**
	 * Config class object.
	 *
	 * @since 0.14.4
	 *
	 * @var Config
	 */
	private $_config = null;

	/**
	 * Constructor.
	 *
	 * @since 0.14.4
	 */
	public function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Run.
	 *
	 * @since 0.14.4
	 */
	public function run() {
		// Disable jquery-migrate on the front-end, if configured.
		if ( ! is_admin() && $this->_config->get_boolean( 'jquerymigrate.disabled' ) ) {
			add_action( 'wp_default_scripts', array( $this, 'disable_jquery_migrate' ) );
		}
	}

	/**
	 * Disable jquery-migrate.
	 *
	 * @since 0.14.4
	 *
	 * @link https://developer.wordpress.org/reference/hooks/wp_default_scripts/
	 * @link https://core.trac.wordpress.org/browser/tags/5.4/src/wp-includes/class.wp-dependencies.php
	 *
	 * @param WP_Scripts $scripts WP_Scripts instance.
	 */
	public function disable_jquery_migrate( $scripts ) {
		if ( isset( $scripts->registered['jquery'] ) ) {
			$script = $scripts->registered['jquery'];

			if ( $script->deps ) {
				$script->deps = array_diff( $script->deps, array( 'jquery-migrate' ) );
			}
		}

		unset( $scripts->registered['jquery-migrate'] );
	}
}
