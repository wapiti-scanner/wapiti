<?php
/**
 * Infinite Scroll Theme Assets
 *
 * Register support for Twenty Thirteen.
 *
 * @package jetpack
 */

/**
 * Add theme support for infinite scroll
 */
function jetpack_twentythirteen_infinite_scroll_init() {
	add_theme_support(
		'infinite-scroll',
		array(
			'container'      => 'content',
			'footer'         => 'page',
			'footer_widgets' => array( 'sidebar-1' ),
		)
	);
}
add_action( 'after_setup_theme', 'jetpack_twentythirteen_infinite_scroll_init' );

/**
 * Enqueue CSS stylesheet with theme styles for Infinite Scroll.
 */
function jetpack_twentythirteen_infinite_scroll_enqueue_styles() {
	if ( wp_script_is( 'the-neverending-homepage' ) ) {
		wp_enqueue_style( 'infinity-twentythirteen', plugins_url( 'twentythirteen.css', __FILE__ ), array( 'the-neverending-homepage' ), '20130409' );
	}
}
add_action( 'wp_enqueue_scripts', 'jetpack_twentythirteen_infinite_scroll_enqueue_styles', 25 );
