<?php
/**
 * Infinite Scroll Theme Assets
 *
 * Register support for @Twenty Eleven and enqueue relevant styles.
 *
 * @package jetpack
 */

/**
 * Add theme support for infinity scroll
 */
function jetpack_twentyeleven_infinite_scroll_init() {
	add_theme_support(
		'infinite-scroll',
		array(
			'container'      => 'content',
			'footer'         => 'page',
			'footer_widgets' => jetpack_twentyeleven_has_footer_widgets(),
		)
	);
}
add_action( 'init', 'jetpack_twentyeleven_infinite_scroll_init' );

/**
 * Enqueue CSS stylesheet with theme styles for infinity.
 */
function jetpack_twentyeleven_infinite_scroll_enqueue_styles() {
	if ( wp_script_is( 'the-neverending-homepage' ) ) {
		// Add theme specific styles.
		wp_enqueue_style( 'infinity-twentyeleven', plugins_url( 'twentyeleven.css', __FILE__ ), array( 'the-neverending-homepage' ), '20121002' );
	}
}
add_action( 'wp_enqueue_scripts', 'jetpack_twentyeleven_infinite_scroll_enqueue_styles', 25 );

/**
 * Do we have footer widgets?
 */
function jetpack_twentyeleven_has_footer_widgets() {
	// Are any of the "Footer Area" sidebars active?
	if ( is_active_sidebar( 'sidebar-3' ) || is_active_sidebar( 'sidebar-4' ) || is_active_sidebar( 'sidebar-5' ) ) {
		return true;
	}

	// If we're on mobile and the Main Sidebar has widgets, it falls below the content, so we have footer widgets.
	if ( function_exists( 'jetpack_is_mobile' ) && jetpack_is_mobile() && is_active_sidebar( 'sidebar-1' ) ) {
		return true;
	}

	return false;
}
