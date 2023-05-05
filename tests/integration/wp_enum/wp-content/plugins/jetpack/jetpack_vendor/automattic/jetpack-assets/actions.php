<?php
/**
 * Action Hooks for Jetpack Assets module.
 *
 * @package automattic/jetpack-assets
 */

// If WordPress's plugin API is available already, use it. If not,
// drop data into `$wp_filter` for `WP_Hook::build_preinitialized_hooks()`.
if ( function_exists( 'add_action' ) ) {
	add_action( 'wp_default_scripts', array( Automattic\Jetpack\Assets::class, 'wp_default_scripts_hook' ) );
} else {
	global $wp_filter;
	// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	$wp_filter['wp_default_scripts'][10][] = array(
		'accepted_args' => 1,
		'function'      => array( Automattic\Jetpack\Assets::class, 'wp_default_scripts_hook' ),
	);
}
