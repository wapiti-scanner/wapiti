<?php
/**
 * Infinite Scroll Theme Assets
 *
 * Register support for Twenty Seventeen.
 *
 * @package jetpack
 */

/**
 * Add theme support for infinite scroll
 */
function jetpack_twentyseventeen_infinite_scroll_init() {
	add_theme_support(
		'infinite-scroll',
		array(
			'container'      => 'main',
			'render'         => 'jetpack_twentyseventeen_infinite_scroll_render',
			'footer'         => 'content',
			'footer_widgets' => jetpack_twentyseventeen_has_footer_widgets(),
		)
	);
}
add_action( 'init', 'jetpack_twentyseventeen_infinite_scroll_init' );

/**
 * Custom render function for Infinite Scroll.
 */
function jetpack_twentyseventeen_infinite_scroll_render() {
	while ( have_posts() ) {
		the_post();
		if ( is_search() ) {
			get_template_part( 'template-parts/post/content', 'search' );
		} else {
			get_template_part( 'template-parts/post/content', get_post_format() );
		}
	}
}

/**
 * Custom function to check for the presence of footer widgets or the social links menu
 */
function jetpack_twentyseventeen_has_footer_widgets() {
	if ( is_active_sidebar( 'sidebar-2' ) ||
		is_active_sidebar( 'sidebar-3' ) ||
		has_nav_menu( 'social' ) ) {

		return true;
	}

	return false;
}

/**
 * Enqueue CSS stylesheet with theme styles for Infinite Scroll.
 */
function jetpack_twentyseventeen_infinite_scroll_enqueue_styles() {
	if ( wp_script_is( 'the-neverending-homepage' ) ) {
		wp_enqueue_style( 'infinity-twentyseventeen', plugins_url( 'twentyseventeen.css', __FILE__ ), array( 'the-neverending-homepage' ), '20161219' );
		wp_style_add_data( 'infinity-twentyseventeen', 'rtl', 'replace' );
	}
}
add_action( 'wp_enqueue_scripts', 'jetpack_twentyseventeen_infinite_scroll_enqueue_styles', 25 );
