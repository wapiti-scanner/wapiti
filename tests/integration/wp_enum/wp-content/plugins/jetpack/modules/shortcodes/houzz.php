<?php
/**
 * Houzz Embed
 *
 * Examples:
 * Post content:
 * - [houzz=http://www.houzz.com/pro/james-crisp]
 * - http://www.houzz.com/pro/james-crisp
 * Blog sidebar: [houzz=http://www.houzz.com/profile/alon w=200 h=300]
 *
 * @package automattic/jetpack
 */

// Register oEmbed provider.
wp_oembed_add_provider( '#https?://(.+?\.)?houzz\.(com|co\.uk|com\.au|de|fr|ru|jp|it|es|dk|se)/.*#i', 'https://www.houzz.com/oembed', true );

/**
 * Display shortcode
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_houzz_shortcode( $atts ) {
	$url  = substr( $atts[0], 1 );
	$args = array();
	if ( isset( $atts['w'] ) && is_numeric( $atts['w'] ) ) {
		$args['width'] = $atts['w'];
	}
	if ( isset( $atts['h'] ) && is_numeric( $atts['h'] ) ) {
		$args['height'] = $atts['h'];
	}
	$oembed = _wp_oembed_get_object();
	return $oembed->get_html( $url, $args );
}
add_shortcode( 'houzz', 'jetpack_houzz_shortcode' );
