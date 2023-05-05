<?php
/**
 * Social Logos
 * Icon Font of the social logos we use on WordPress.com and in Jetpack
 *
 * Reference: https://github.com/Automattic/social-logos
 *
 * @package automattic/jetpack
 */

define( 'JETPACK_SOCIAL_LOGOS_URL', plugin_dir_url( __FILE__ ) . 'social-logos/' );
define( 'JETPACK_SOCIAL_LOGOS_DIR', plugin_dir_path( __FILE__ ) . 'social-logos/' );

/**
 * Globally registers the 'social-logos' style and font.
 *
 * This ensures any theme or plugin using it is on the latest version of Social Logos, and helps to avoid conflicts.
 */
function jetpack_register_social_logos() {
	if ( ! wp_style_is( 'social-logos', 'registered' ) ) {
		/** This filter is documented in modules/sharedaddy/sharing.php */
		$post_fix = apply_filters( 'jetpack_should_use_minified_assets', true ) ? '.min' : '';
		wp_register_style(
			'social-logos',
			JETPACK_SOCIAL_LOGOS_URL . 'social-logos' . $post_fix . '.css',
			false,
			JETPACK__VERSION
		);
	}
}
add_action( 'init', 'jetpack_register_social_logos', 1 );
