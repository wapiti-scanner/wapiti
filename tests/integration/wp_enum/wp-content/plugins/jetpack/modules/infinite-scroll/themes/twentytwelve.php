<?php
/**
 * Infinite Scroll Theme Assets
 *
 * Register support for Twenty Twelve and enqueue relevant styles.
 *
 * @package jetpack
 */

/**
 * Add theme support for infinite scroll
 */
function jetpack_twentytwelve_infinite_scroll_init() {
	add_theme_support(
		'infinite-scroll',
		array(
			'container'      => 'content',
			'footer'         => 'page',
			'footer_widgets' => jetpack_twentytwelve_has_footer_widgets(),
		)
	);
}
add_action( 'after_setup_theme', 'jetpack_twentytwelve_infinite_scroll_init' );

/**
 * Enqueue CSS stylesheet with theme styles for infinity.
 */
function jetpack_twentytwelve_infinite_scroll_enqueue_styles() {
	if ( wp_script_is( 'the-neverending-homepage' ) ) {
		// Add theme specific styles.
		wp_enqueue_style( 'infinity-twentytwelve', plugins_url( 'twentytwelve.css', __FILE__ ), array( 'the-neverending-homepage' ), '20120817' );
	}
}
add_action( 'wp_enqueue_scripts', 'jetpack_twentytwelve_infinite_scroll_enqueue_styles', 25 );

/**
 * Do we have footer widgets?
 */
function jetpack_twentytwelve_has_footer_widgets() {
	if ( function_exists( 'jetpack_is_mobile' ) && jetpack_is_mobile() ) {
		if ( is_front_page() && ( is_active_sidebar( 'sidebar-2' ) || is_active_sidebar( 'sidebar-3' ) ) ) {
			return true;
		} elseif ( is_active_sidebar( 'sidebar-1' ) ) {
			return true;
		}
	}

	return false;
}
