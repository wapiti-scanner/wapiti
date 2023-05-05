<?php
/**
 * Fixes issues with the Official Bitly for WordPress
 * https://wordpress.org/plugins/bitly/
 *
 * @package automattic/jetpack
 */

if ( isset( $GLOBALS['bitly'] ) ) {
	if ( method_exists( $GLOBALS['bitly'], 'og_tags' ) ) {
		remove_action( 'wp_head', array( $GLOBALS['bitly'], 'og_tags' ) );
	}
		add_action( 'wp_head', 'jetpack_bitly_og_tag', 100 );
}

/**
 * Adds bitly OG tags.
 */
function jetpack_bitly_og_tag() {
	if ( has_filter( 'wp_head', 'jetpack_og_tags' ) === false ) {
		// Add the bitly part again back if we don't have any jetpack_og_tags added.
		if ( method_exists( $GLOBALS['bitly'], 'og_tags' ) ) {
			$GLOBALS['bitly']->og_tags();
		}
	} elseif ( isset( $GLOBALS['posts'] ) && $GLOBALS['posts'][0]->ID > 0 ) {
		printf( "<meta property=\"bitly:url\" content=\"%s\" /> \n", esc_attr( $GLOBALS['bitly']->get_bitly_link_for_post_id( $GLOBALS['posts'][0]->ID ) ) );
	}
}
