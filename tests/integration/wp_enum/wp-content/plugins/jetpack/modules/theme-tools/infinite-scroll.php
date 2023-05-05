<?php
/**
 * Theme Tools: Infinite Scroll functions.
 *
 * @package automattic/jetpack
 */

/**
 * Load theme's infinite scroll annotation file, if present in the IS plugin.
 * The `setup_theme` action is used because the annotation files should be using `after_setup_theme` to register support for IS.
 *
 * As released in Jetpack 2.0, a child theme's parent wasn't checked for in the plugin's bundled support, hence the convoluted way the parent is checked for now.
 *
 * @uses is_admin, wp_get_theme, apply_filters
 * @action setup_theme
 * @return null
 */
function jetpack_load_infinite_scroll_annotation() {
	if ( is_admin() && isset( $_GET['page'] ) && 'jetpack' === $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Function loads theme specific IS file provided by Jetpack if possible.
		$theme = wp_get_theme();

		if ( ! is_a( $theme, 'WP_Theme' ) && ! is_array( $theme ) ) {
			return;
		}

		/** This filter is already documented in modules/infinite-scroll/infinity.php */
		$customization_file = apply_filters( 'infinite_scroll_customization_file', __DIR__ . "/infinite-scroll/themes/{$theme['Stylesheet']}.php", $theme['Stylesheet'] );

		if ( is_readable( $customization_file ) ) {
			require_once $customization_file;
		} elseif ( ! empty( $theme['Template'] ) ) {
			$customization_file = __DIR__ . "/infinite-scroll/themes/{$theme['Template']}.php";

			if ( is_readable( $customization_file ) ) {
				require_once $customization_file;
			}
		}
	}
}
add_action( 'setup_theme', 'jetpack_load_infinite_scroll_annotation' );

/**
 * Prevent IS from being activated if theme doesn't support it
 *
 * @filter jetpack_can_activate_infinite-scroll
 * @return bool
 */
function jetpack_can_activate_infinite_scroll() {
	return (bool) current_theme_supports( 'infinite-scroll' );
}
add_filter( 'jetpack_can_activate_infinite-scroll', 'jetpack_can_activate_infinite_scroll' );
