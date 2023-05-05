<?php
/**
 * Loads the devicepx library which improves the resolution of gravatars and
 * wordpress.com uploads on hi-res and zoomed browsers.
 *
 * This feature will only be activated for themes that declare their support.
 * This can be done by adding code similar to the following during the
 * 'after_setup_theme' action:
 *
 * add_theme_support( 'jetpack-devicepx' );
 *
 * @package automattic/jetpack
 */

/**
 * Enqueue the devicepx JS library, if enabled. The feature must
 * be enabled earlier during `after_setup_theme`.
 *
 * @uses current_theme_supports, add_action
 */
function jetpack_devicepx_init() {
	if ( current_theme_supports( 'jetpack-devicepx' ) ) {
		add_action( 'wp_enqueue_scripts', 'jetpack_devicepx_enqueue' );
		add_action( 'customize_controls_enqueue_scripts', 'jetpack_devicepx_enqueue' );
		add_action( 'admin_enqueue_scripts', 'jetpack_devicepx_enqueue' );
	}
}

// Use a late priority to ensure that plugins and themes can enable or disable this feature.
add_action( 'init', 'jetpack_devicepx_init', 99 );

/**
 * Enqueue the devicepx JS library.
 *
 * @uses wp_enqueue_script
 */
function jetpack_devicepx_enqueue() {
	wp_enqueue_script( 'devicepx', 'https://s0.wp.com/wp-content/js/devicepx-jetpack.js', array(), gmdate( 'oW' ), true );
}
