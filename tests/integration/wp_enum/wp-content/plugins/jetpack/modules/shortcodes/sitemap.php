<?php
/**
 * Sitemap shortcode.
 *
 * Usage: [sitemap]
 *
 * @package automattic/jetpack
 */

add_shortcode( 'sitemap', 'jetpack_sitemap_shortcode' );

/**
 * Renders a tree of pages.
 *
 * @since 4.5.0
 *
 * @return string
 */
function jetpack_sitemap_shortcode() {
	$tree = wp_list_pages(
		array(
			'title_li' => '<b><a href="/">' . esc_html( get_bloginfo( 'name' ) ) . '</a></b>',
			'exclude'  => get_option( 'page_on_front' ),
			'echo'     => false,
		)
	);
	return empty( $tree )
		? ''
		: '<ul class="jetpack-sitemap-shortcode">' . $tree . '</ul>';
}
