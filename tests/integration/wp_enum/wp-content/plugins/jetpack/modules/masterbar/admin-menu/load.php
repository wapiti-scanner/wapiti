<?php
/**
 * Admin Menu loader.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Tracking;

/**
 * Checks whether the navigation customizations should be performed for the given class.
 *
 * @param string $admin_menu_class Class name.
 *
 * @return bool
 */
function should_customize_nav( $admin_menu_class ) {
	// Make sure the class extends the base admin menu class.
	if ( ! is_subclass_of( $admin_menu_class, Base_Admin_Menu::class ) ) {
		return false;
	}

	$is_api_request = defined( 'REST_REQUEST' ) && REST_REQUEST || isset( $_SERVER['REQUEST_URI'] ) && 0 === strpos( filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ), '/?rest_route=%2Fwpcom%2Fv2%2Fadmin-menu' );

	// No nav customizations on WP Admin of Atomic sites when SSO is disabled.
	if ( is_a( $admin_menu_class, Atomic_Admin_Menu::class, true ) && ! $is_api_request && ! \Jetpack::is_module_active( 'sso' ) ) {
		return false;
	}

	// No nav customizations on WP Admin of Jetpack sites.
	if ( is_a( $admin_menu_class, Jetpack_Admin_Menu::class, true ) && ! $is_api_request ) {
		return false;
	}

	return true;
}

/**
 * Gets the name of the class that customizes the admin menu.
 *
 * @return string Class name.
 */
function get_admin_menu_class() {
	// WordPress.com Atomic sites.
	if ( ( new Host() )->is_woa_site() ) {

		// DIFM Lite In Progress Atomic Sites. Uses the same menu used for domain-only sites.
		// Ignore this check if we are in a support session.
		$is_difm_lite_in_progress = wpcomsh_is_site_sticker_active( 'difm-lite-in-progress' );
		$is_support_session       = defined( 'WPCOM_SUPPORT_SESSION' ) && WPCOM_SUPPORT_SESSION;
		if ( $is_difm_lite_in_progress && ! $is_support_session ) {
			require_once __DIR__ . '/class-domain-only-admin-menu.php';
			return Domain_Only_Admin_Menu::class;
		}

		require_once __DIR__ . '/class-atomic-admin-menu.php';
		return Atomic_Admin_Menu::class;
	}

	// WordPress.com Simple sites.
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		$blog_id = get_current_blog_id();

		// Domain-only sites.
		$blog_options   = get_blog_option( $blog_id, 'options' );
		$is_domain_only = ! empty( $blog_options['is_domain_only'] );
		if ( $is_domain_only ) {
			require_once __DIR__ . '/class-domain-only-admin-menu.php';
			return Domain_Only_Admin_Menu::class;
		}

		// DIFM Lite In Progress Sites. Uses the same menu used for domain-only sites.
		// Ignore this check if we are in a support session.
		$is_difm_lite_in_progress = has_blog_sticker( 'difm-lite-in-progress' );
		$is_support_session       = defined( 'WPCOM_SUPPORT_SESSION' ) && WPCOM_SUPPORT_SESSION;
		if ( $is_difm_lite_in_progress && ! $is_support_session ) {
			require_once __DIR__ . '/class-domain-only-admin-menu.php';
			return Domain_Only_Admin_Menu::class;
		}

		// P2 sites.
		require_once WP_CONTENT_DIR . '/lib/wpforteams/functions.php';
		if ( \WPForTeams\is_wpforteams_site( $blog_id ) ) {
			require_once __DIR__ . '/class-p2-admin-menu.php';
			return P2_Admin_Menu::class;
		}

		// Rest of simple sites.
		require_once __DIR__ . '/class-wpcom-admin-menu.php';
		return WPcom_Admin_Menu::class;
	}

	// Jetpack sites.
	require_once __DIR__ . '/class-jetpack-admin-menu.php';
	return Jetpack_Admin_Menu::class;
}

/**
 * Filters the name of the class that customizes the admin menu. It should extends the `Base_Admin_Menu` class.
 *
 * @module masterbar
 *
 * @since 9.6.0
 *
 * @param string $admin_menu_class Class name.
 */
$admin_menu_class = apply_filters( 'jetpack_admin_menu_class', get_admin_menu_class() );
if ( should_customize_nav( $admin_menu_class ) ) {
	/** The admin menu singleton instance. @var Base_Admin_Menu $instance */
	$admin_menu_class::get_instance();

	/**
	 * Trigger an event when the user uses the dashboard quick switcher.
	 *
	 * @param string $screen The current screen.
	 * @param string $view The view the user choosed to go to.
	 */
	function dashboard_quick_switcher_record_usage( $screen, $view ) {
		require_once __DIR__ . '/class-dashboard-switcher-tracking.php';

		$tracking = new Dashboard_Switcher_Tracking(
			new Tracking( Dashboard_Switcher_Tracking::get_jetpack_tracking_product() ),
			array( Dashboard_Switcher_Tracking::class, 'wpcom_tracks_record_event' ),
			Dashboard_Switcher_Tracking::get_plan()
		);

		$tracking->record_switch_event( $screen, $view );
	}

	\add_action( 'jetpack_dashboard_switcher_changed_view', __NAMESPACE__ . '\dashboard_quick_switcher_record_usage', 10, 2 );
} else {
	\add_filter( 'jetpack_load_admin_menu_class', '__return_false' );
}
