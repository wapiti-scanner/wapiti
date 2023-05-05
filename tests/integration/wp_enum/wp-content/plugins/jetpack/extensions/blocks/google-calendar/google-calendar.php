<?php
/**
 * Google Calendar Block.
 *
 * @since 8.3.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Google_Calendar;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'google-calendar';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'render_callback' => __NAMESPACE__ . '\load_assets',
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Google Calendar block registration/dependency declaration.
 *
 * @param array $attr Array containing the Google Calendar block attributes.
 * @return string
 */
function load_assets( $attr ) {
	$height  = isset( $attr['height'] ) ? $attr['height'] : '600';
	$url     = isset( $attr['url'] )
		? Jetpack_Gutenberg::validate_block_embed_url( $attr['url'], array( 'calendar.google.com' ) ) :
		'';
	$classes = Blocks::classes( FEATURE_NAME, $attr );

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	if ( empty( $url ) ) {
		return '';
	}

	$sandbox = 'allow-scripts allow-same-origin allow-popups';
	if ( Blocks::is_amp_request() ) {
		$noscript_src = str_replace(
			'//calendar.google.com/calendar/embed',
			'//calendar.google.com/calendar/htmlembed',
			$url
		);

		$iframe = sprintf(
			'<amp-iframe src="%1$s" frameborder="0" scrolling="no" height="%2$d" layout="fixed-height" sandbox="%3$s">%4$s%5$s</amp-iframe>',
			esc_url( $url ),
			absint( $height ),
			esc_attr( $sandbox ),
			sprintf(
				'<a href="%s" placeholder>%s</a>',
				esc_url( $url ),
				esc_html__( 'Google Calendar', 'jetpack' )
			),
			sprintf(
				'<noscript><iframe src="%1$s" frameborder="0" scrolling="no" sandbox="%2$s"></iframe></noscript>',
				esc_url( $noscript_src ),
				esc_attr( $sandbox )
			)
		);
	} else {
		$iframe = sprintf(
			'<iframe src="%1$s" frameborder="0" style="border:0" scrolling="no" height="%2$d" width="100%%" sandbox="%3$s"></iframe>',
			esc_url( $url ),
			absint( $height ),
			esc_attr( $sandbox )
		);
	}

	return sprintf( '<div class="%s">%s</div>', esc_attr( $classes ), $iframe );
}
