<?php
/**
 * Scribd Shortcode
 *
 * [scribd id=DOCUMENT_ID key=DOCUMENT_KEY mode=MODE]
 * DOCUMENT_ID is an integer (also used as an object_id)
 * DOCUMENT_KEY is an alphanumeric hash ('-' character as well)
 * MODE can be 'list', 'book', 'slide', 'slideshow', or 'tile'
 *
 * [scribd id=39027960 key=key-3kaiwcjqhtipf25m8tw mode=list]
 *
 * @package automattic/jetpack
 */

/**
 * Register Scribd shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function scribd_shortcode_handler( $atts ) {
	$atts = shortcode_atts(
		array(
			'id'   => 0,
			'key'  => 0,
			'mode' => '',
		),
		$atts,
		'scribd'
	);

	$modes = array( 'list', 'book', 'slide', 'slideshow', 'tile' );

	$atts['id'] = (int) $atts['id'];
	if ( preg_match( '/^[A-Za-z0-9-]+$/', $atts['key'], $m ) ) {
		$atts['key'] = $m[0];

		if ( ! in_array( $atts['mode'], $modes, true ) ) {
			$atts['mode'] = '';
		}

		return scribd_shortcode_markup( $atts );
	} else {
		return '';
	}
}

/**
 * Display the shortcode.
 *
 * @param array $atts Shortcode attributes.
 * @return string The rendered shortcode.
 */
function scribd_shortcode_markup( $atts ) {
	$sandbox = class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request()
		? 'sandbox="allow-popups allow-scripts allow-same-origin"'
		: '';

	$url = add_query_arg(
		array(
			'start_page' => '1',
			'view_mode'  => esc_attr( $atts['mode'] ),
			'access_key' => esc_attr( $atts['key'] ),
		),
		esc_url(
			sprintf(
				'https://www.scribd.com/embeds/%1$d/content',
				absint( $atts['id'] )
			)
		)
	);

	return sprintf(
		'<iframe class="scribd_iframe_embed" src="%1$s" %2$s data-auto-height="true" scrolling="no" id="scribd_%3$d" width="100%%" height="500" frameborder="0"></iframe>
		<div style="font-size:10px;text-align:center;width:100%%"><a href="https://www.scribd.com/doc/%3$d" rel="noopener noreferrer" target="_blank">%4$s</a></div>',
		$url,
		$sandbox,
		absint( $atts['id'] ),
		esc_html__( 'View this document on Scribd', 'jetpack' )
	);
}
add_shortcode( 'scribd', 'scribd_shortcode_handler' );

/**
 * Scribd supports HTTPS, so use that endpoint to get HTTPS-compatible embeds.
 *
 * @param array $providers Array of oEmbed providers.
 */
function scribd_https_oembed( $providers ) {
	if ( isset( $providers['#https?://(www\.)?scribd\.com/doc/.*#i'] ) ) {
		$providers['#https?://(www\.)?scribd\.com/doc/.*#i'][0] = 'https://www.scribd.com/services/oembed';
	}

	return $providers;
}
add_filter( 'oembed_providers', 'scribd_https_oembed' );
