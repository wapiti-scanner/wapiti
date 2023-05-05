<?php
/**
 * Google+ embeds
 * Google+ has shut down. Output the link for history's sake.
 * Other than that, there's not much we can do.
 *
 * @package automattic/jetpack
 */

define( 'JETPACK_GOOGLEPLUS_EMBED_REGEX', '#^https?://plus\.(sandbox\.)?google\.com/(u/\d+/)?([^/]+)/posts/([^/]+)$#' );

/*
 * Example URL: https://plus.google.com/114986219448604314131/posts/LgHkesWCmJo
 * Alternate example: https://plus.google.com/u/0/100004581596612508203/posts/2UKwN67MBQs  (note the /u/0/)
 */
wp_embed_register_handler( 'googleplus', JETPACK_GOOGLEPLUS_EMBED_REGEX, 'jetpack_deprecated_embed_handler' );

add_shortcode( 'googleplus', 'jetpack_googleplus_shortcode_handler' );

/**
 * Display the Google+ shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_googleplus_shortcode_handler( $atts ) {
	global $wp_embed;

	if ( empty( $atts['url'] ) ) {
		return;
	}

	if ( ! preg_match( JETPACK_GOOGLEPLUS_EMBED_REGEX, $atts['url'] ) ) {
		return;
	}

	return sprintf( '<p>%s</p>', $wp_embed->shortcode( $atts, $atts['url'] ) );
}
