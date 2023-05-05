<?php
/**
 * Embed support for Medium
 *
 * Supported formats:
 * - Profiles: https://medium.com/@jeherve
 * - Stories: https://medium.com/@jeherve/this-is-a-story-19f582daaf5b
 * - And all the above in shortcode formats:
 * [medium url="https://medium.com/@jeherve/this-is-a-story-19f582daaf5b" width="100%" border="false" collapsed="true"]
 *
 * @package automattic/jetpack
 */

// Faux-oembed support for Medium permalinks.
wp_embed_register_handler( 'medium', '#^https?://medium.com/([a-zA-z0-9-_@]+)#', 'jetpack_embed_medium_oembed' );

/**
 * Callback to modify output of embedded Medium posts.
 *
 * @param array $matches Regex partial matches against the URL passed.
 * @param array $attr    Attributes received in embed response.
 * @param array $url     Requested URL to be embedded.
 */
function jetpack_embed_medium_oembed( $matches, $attr, $url ) {
	$attr        = jetpack_embed_medium_args( $attr );
	$attr['url'] = $url;

	return jetpack_embed_medium_embed_html( $attr );
}

/**
 * Return custom markup to display a Medium profile, collection, or story.
 *
 * @param array $args Attributes received in embed response.
 */
function jetpack_embed_medium_embed_html( $args ) {
	$args = jetpack_embed_medium_args( $args );

	if ( empty( $args['url'] ) ) {
		return;
	}

	$args['type'] = jetpack_embed_medium_get_embed_type( $args['url'] );

	if ( 'collection' === $args['type'] ) {
		return sprintf(
			'<a href="%1$s" target="_blank" rel="noopener noreferrer">%2$s</a>',
			esc_url( $args['url'] ),
			esc_html__( 'View this collection on Medium.com', 'jetpack' )
		);
	}

	wp_enqueue_script(
		'medium-embed',
		'https://static.medium.com/embed.js',
		array(),
		JETPACK__VERSION,
		true
	);

	return sprintf(
		'<a class="m-%1$s" href="%2$s" target="_blank" data-width="%3$s" data-border="%4$s" data-collapsed="%5$s">%6$s</a>',
		esc_attr( $args['type'] ),
		esc_url( $args['url'] ),
		esc_attr( $args['width'] ),
		esc_attr( $args['border'] ),
		esc_attr( $args['collapsed'] ),
		esc_html__( 'View at Medium.com', 'jetpack' )
	);
}

/**
 * Shortcode support that allows passing in URL
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_embed_medium_shortcode( $atts ) {
	$atts = jetpack_embed_medium_args( $atts );

	if ( ! empty( $atts['url'] ) ) {
		global $wp_embed;
		return $wp_embed->shortcode( $atts, $atts['url'] );
	} elseif ( current_user_can( 'edit_posts' ) ) {
		return esc_html__( 'You did not provide a valid Medium URL.', 'jetpack' );
	} else {
		return '<!-- Missing Medium URL -->';
	}
}
add_shortcode( 'medium', 'jetpack_embed_medium_shortcode' );

/**
 * Get embed type (profile, collection, or story) based on Medium URL.
 *
 * @param string $url Medium URL.
 */
function jetpack_embed_medium_get_embed_type( $url ) {
	$url_path = wp_parse_url( $url, PHP_URL_PATH );
	if ( preg_match( '/^\/@[\.\w]+$/', $url_path ) ) {
		return 'profile';
	} elseif ( preg_match( '/^\/(?:s)\/(.+)$/', $url_path ) ) {
		return 'collection';
	}

	return 'story';
}

/**
 * Process Medium shortcode attributes.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_embed_medium_args( $atts ) {
	return shortcode_atts(
		array(
			'url'       => '',
			'width'     => '400',
			'border'    => true,
			'collapsed' => false,
		),
		$atts,
		'medium'
	);
}
