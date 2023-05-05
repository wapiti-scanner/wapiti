<?php
/**
 * Image Compare Block.
 *
 * @since 8.6
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\ImageCompare;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'image-compare';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\load_assets' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Image Compare block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the image-compare block attributes.
 * @param string $content String containing the image-compare block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );
	wp_localize_script(
		'jetpack-block-' . sanitize_title_with_dashes( FEATURE_NAME ),
		'imageCompareHandle',
		array(
			'msg' => __( 'Slide to compare images', 'jetpack' ),
		)
	);
	if ( Blocks::is_amp_request() ) {
		$content = preg_replace(
			'#<div class="juxtapose".+?</div>#s',
			render_amp( $attr ),
			$content
		);
	}

	return $content;
}

/**
 * Render image compare block for AMP
 *
 * @param array $attr Array containing the image-compare block attributes.
 *
 * @return string Markup for amp-image-slider.
 */
function render_amp( $attr ) {
	$img_before = $attr['imageBefore'];
	$img_after  = $attr['imageAfter'];

	$width  = ! empty( $img_before['width'] ) ? absint( $img_before['width'] ) : 0;
	$height = ! empty( $img_before['height'] ) ? absint( $img_before['height'] ) : 0;

	// As fallback, give 1:1 aspect ratio.
	if ( ! $width || ! $height ) {
		$width  = 1;
		$height = 1;
	}

	return sprintf(
		'<amp-image-slider layout="responsive" width="%1$s" height="%2$s"> <amp-img id="%3$d" src="%4$s" alt="%5$s" layout="fill"></amp-img> <amp-img id="%6$d" src="%7$s" alt="%8$s" layout="fill"></amp-img></amp-image-slider>',
		esc_attr( $width ),
		esc_attr( $height ),
		absint( $img_before['id'] ),
		esc_url( $img_before['url'] ),
		esc_attr( $img_before['alt'] ),
		absint( $img_after['id'] ),
		esc_url( $img_after['url'] ),
		esc_attr( $img_after['alt'] )
	);
}
