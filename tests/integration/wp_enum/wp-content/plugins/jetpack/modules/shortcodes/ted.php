<?php
/**
 * TED Player embed code
 * http://www.ted.com
 *
 * Examples:
 * http://www.ted.com/talks/view/id/210
 * http://www.ted.com/talks/marc_goodman_a_vision_of_crimes_in_the_future.html
 * [ted id="210" lang="en"]
 * [ted id="http://www.ted.com/talks/view/id/210" lang="en"]
 * [ted id=1539 lang=fr width=560 height=315]
 *
 * @package automattic/jetpack
 */

wp_oembed_add_provider( '!https?://(www\.)?ted.com/talks/view/id/.+!i', 'https://www.ted.com/talks/oembed.json', true );
wp_oembed_add_provider( '!https?://(www\.)?ted.com/talks/[a-zA-Z\-\_]+\.html!i', 'https://www.ted.com/talks/oembed.json', true );

/**
 * Get the unique ID of a TED video.
 * Used in Jetpack_Media_Meta_Extractor.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_shortcode_get_ted_id( $atts ) {
	return ( ! empty( $atts['id'] ) ? $atts['id'] : 0 );
}

/**
 * Handle Ted Shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function shortcode_ted( $atts ) {
	global $wp_embed;

	$defaults = array(
		'id'     => '',
		'width'  => '',
		'height' => '',
		'lang'   => 'en',
	);
	$atts     = shortcode_atts( $defaults, $atts, 'ted' );

	if ( empty( $atts['id'] ) ) {
		return '<!-- Missing TED ID -->';
	}

	$url = '';
	if ( preg_match( '#^[\d]+$#', $atts['id'], $matches ) ) {
		$url = 'https://ted.com/talks/view/id/' . $matches[0];
	} elseif ( preg_match( '#^https?://(www\.)?ted\.com/talks/view/id/[0-9]+$#', $atts['id'], $matches ) ) {
		$url = set_url_scheme( $matches[0], 'https' );
	}

	unset( $atts['id'] );

	$args         = array();
	$embed_size_w = get_option( 'embed_size_w' );

	if ( is_numeric( $atts['width'] ) ) {
		$args['width'] = $atts['width'];
	} elseif ( $embed_size_w ) {
		$args['width'] = $embed_size_w;
	} elseif ( ! empty( $GLOBALS['content_width'] ) ) {
		$args['width'] = (int) $GLOBALS['content_width'];
	} else {
		$args['width'] = 500;
	}

	// Default to a 16x9 aspect ratio if there's no height set.
	if ( is_numeric( $atts['height'] ) ) {
		$args['height'] = $atts['height'];
	} else {
		$args['height'] = $args['width'] * 0.5625;
	}

	if ( ! empty( $atts['lang'] ) ) {
		$args['lang'] = sanitize_key( $atts['lang'] );
		add_filter( 'oembed_fetch_url', 'ted_filter_oembed_fetch_url', 10, 3 );
	}
	$retval = $wp_embed->shortcode( $args, $url );
	remove_filter( 'oembed_fetch_url', 'ted_filter_oembed_fetch_url', 10 );

	return $retval;
}
add_shortcode( 'ted', 'shortcode_ted' );

/**
 * Filter the request URL to also include the $lang parameter
 *
 * @param string $provider URL of provider that supplies the tweet we're requesting.
 * @param string $url      URL of tweet to embed.
 * @param array  $args     Parameters supplied to shortcode and passed to wp_oembed_get.
 */
function ted_filter_oembed_fetch_url( $provider, $url, $args ) {
	return add_query_arg( 'lang', $args['lang'], $provider );
}

/**
 * Filter the oembed html to set the sandbox attribute in the iframe
 *
 * @param string|false $cache The cached HTML result, stored in post meta.
 * @param string       $url   The attempted embed URL.
 *
 * @return string|false
 */
function ted_filter_oembed_amp_iframe( $cache, $url ) {
	if ( is_string( $cache )
		&& strpos( $url, 'ted.com' )
	) {
		$cache = preg_replace(
			'/src=[\'"].*?[\'"]/',
			'$0 sandbox="allow-popups allow-scripts allow-same-origin"',
			$cache
		);
	}

	return $cache;
}
add_filter( 'embed_oembed_html', 'ted_filter_oembed_amp_iframe', 10, 2 );
