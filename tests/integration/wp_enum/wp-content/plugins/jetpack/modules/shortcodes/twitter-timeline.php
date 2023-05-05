<?php
/**
 * Twitter Timeline Shortcode.
 *
 * Examples:
 * [twitter-timeline username=jetpack]
 *
 * @package automattic/jetpack
 */

/**
 * Render the Twitter shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function twitter_timeline_shortcode( $atts ) {
	$default_atts = array(
		'username' => '',
		'id'       => '',
		'width'    => '450',
		'height'   => '282',
	);

	$atts = shortcode_atts( $default_atts, $atts, 'twitter-timeline' );

	$atts['username'] = preg_replace( '/[^A-Za-z0-9_]+/', '', $atts['username'] );

	if ( empty( $atts['username'] ) && ! is_numeric( $atts['id'] ) ) {
		return '<!-- ' . __( 'Must specify Twitter Timeline id or username.', 'jetpack' ) . ' -->';
	}

	$output = '<a class="twitter-timeline"';

	/** This filter is documented in modules/shortcodes/tweet.php */
	$partner = apply_filters( 'jetpack_twitter_partner_id', 'jetpack' );
	if ( ! empty( $partner ) ) {
		$output .= ' data-partner="' . esc_attr( $partner ) . '"';
	}
	if ( is_numeric( $atts['width'] ) ) {
		$output .= ' data-width="' . esc_attr( $atts['width'] ) . '"';
	}
	if ( is_numeric( $atts['height'] ) ) {
		$output .= ' data-height="' . esc_attr( $atts['height'] ) . '"';
	}
	if ( is_numeric( $atts['id'] ) ) {
		$output .= ' data-widget-id="' . esc_attr( $atts['id'] ) . '"';
	}
	if ( ! empty( $atts['username'] ) ) {
		$output .= ' href="' . esc_url( 'https://twitter.com/' . $atts['username'] ) . '"';
	}

	$output .= '>';

	$output .= sprintf(
		/* Translators: placeholder is a Twitter username. */
		__( 'Tweets by @%s', 'jetpack' ),
		$atts['username']
	);

	$output .= '</a>';

	wp_enqueue_script( 'jetpack-twitter-timeline' );

	return $output;
}
add_shortcode( 'twitter-timeline', 'twitter_timeline_shortcode' );

/**
 * Enqueue the js used by the Twitter shortcode.
 */
function twitter_timeline_js() {
	if ( is_customize_preview() ) {
		wp_enqueue_script( 'jetpack-twitter-timeline' );
	}
}
add_action( 'wp_enqueue_scripts', 'twitter_timeline_js' );
