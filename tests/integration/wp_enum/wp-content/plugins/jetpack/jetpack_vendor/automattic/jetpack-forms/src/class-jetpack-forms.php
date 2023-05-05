<?php
/**
 * Package description here
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms;

use Automattic\Jetpack\Forms\ContactForm\Util;
use Automattic\Jetpack\Forms\Dashboard\Dashboard;
use Automattic\Jetpack\Forms\Dashboard\Dashboard_View_Switch;
/**
 * Understands the Jetpack Forms package.
 */
class Jetpack_Forms {

	const PACKAGE_VERSION = '0.14.1';

	/**
	 * Load the contact form module.
	 */
	public static function load_contact_form() {
		Util::init();

		if ( is_admin() && self::is_feedback_dashboard_enabled() ) {
			$view_switch = new Dashboard_View_Switch();

			$dashboard = new Dashboard( $view_switch );
			$dashboard->init();
		}

		if ( is_admin() && apply_filters( 'tmp_grunion_allow_editor_view', true ) ) {
			add_action( 'current_screen', '\Automattic\Jetpack\Forms\ContactForm\Editor_View::add_hooks' );
		}

		add_action( 'init', '\Automattic\Jetpack\Forms\ContactForm\Util::register_pattern' );

		add_action( 'rest_api_init', array( new WPCOM_REST_API_V2_Endpoint_Forms(), 'register_rest_routes' ) );
	}

	/**
	 * Get the plugin URL.
	 */
	public static function plugin_url() {
		return plugin_dir_url( __FILE__ );
	}

	/**
	 * Returns true if the feedback dashboard is enabled.
	 *
	 * @return boolean
	 */
	public static function is_feedback_dashboard_enabled() {
		/**
		 * Enable the new Jetpack Forms dashboard.
		 *
		 * @module contact-form
		 * @since 0.3.0
		 *
		 * @param bool false Should the new Jetpack Forms dashboard be enabled? Default to false.
		 */
		return apply_filters( 'jetpack_forms_dashboard_enable', false );
	}
}
