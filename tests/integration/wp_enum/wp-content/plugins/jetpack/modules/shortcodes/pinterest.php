<?php
/**
 * Pinterest embeds
 *
 * Based on "Board Widget" example here: http://business.pinterest.com/widget-builder/#code
 *
 * Example URL: https://pinterest.com/pin/129056345550241149/
 * Second Example URL: https://uk.pinterest.com/annsawesomepins/travel/
 *
 * @package automattic/jetpack
 */

wp_embed_register_handler(
	'pinterest',
	'#'
	. 'https?://'
	. '(?:www\.)?'
	. '(?:[a-z]{2}\.)?'
	. 'pinterest\.[a-z.]+/'
	. '([^/]+)'
	. '(/[^/]+)?'
	. '#',
	'pinterest_embed_handler'
);

/**
 * Callback to modify output of embedded Pinterest posts.
 *
 * @param array $matches Regex partial matches against the URL passed.
 * @param array $attr    Attributes received in embed response.
 * @param array $url     Requested URL to be embedded.
 */
function pinterest_embed_handler( $matches, $attr, $url ) {
	// Pinterest's JS handles making the embed.
	$script_src = '//assets.pinterest.com/js/pinit.js';

	wp_enqueue_script( 'pinterest-embed', $script_src, array(), JETPACK__VERSION, true );

	$path = wp_parse_url( $url, PHP_URL_PATH );
	if ( 0 === strpos( $path, '/pin/' ) ) {
		$embed_type = 'embedPin';
	} elseif ( preg_match( '#^/([^/]+)/?$#', $path ) ) {
		$embed_type = 'embedUser';
	} elseif ( preg_match( '#^/([^/]+)/([^/]+)/?$#', $path ) ) {
		$embed_type = 'embedBoard';
	} else {
		if ( current_user_can( 'edit_posts' ) ) {
			return __( 'Sorry, that Pinterest URL was not recognized.', 'jetpack' );
		}
		return;
	}

	$return = sprintf( '<a data-pin-do="%s" href="%s"></a>', esc_attr( $embed_type ), esc_url( $url ) );

	// If we're generating an embed view for the WordPress Admin via ajax.
	if ( doing_action( 'wp_ajax_parse-embed' ) ) {
		$return .= sprintf(
			'<script src="%s"></script>', // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
			esc_url( $script_src )
		);
	}

	return $return;
}
