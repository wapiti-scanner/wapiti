<?php
/**
 * Legacy global scope functions.
 *
 * @package automattic/jetpack-compat
 */

// If WordPress's plugin API is available already, use it. If not,
// drop data into `$wp_filter` for `WP_Hook::build_preinitialized_hooks()`.
if ( function_exists( 'add_filter' ) ) {
	$add_filter = 'add_filter';
	$add_action = 'add_action';
} else {
	$add_filter = function ( $name, $cb, $priority = 10, $accepted_args = 1 ) {
		global $wp_filter;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$wp_filter[ $name ][ $priority ][] = array(
			'accepted_args' => $accepted_args,
			'function'      => $cb,
		);
	};
	$add_action = $add_filter;
}

/**
 * Load necessary functions.
 */
function jetpack_compat_require_defined_functions() {
	require_once __DIR__ . '/lib/tracks/client.php';
}

$add_action( 'plugins_loaded', 'jetpack_compat_require_defined_functions' );
