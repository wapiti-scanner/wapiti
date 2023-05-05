<?php
/**
 * Slideshow Block.
 *
 * @since 7.1.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Slideshow;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'slideshow';
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
 * Slideshow block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the slideshow block attributes.
 * @param string $content String containing the slideshow block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );
	if ( Blocks::is_amp_request() ) {
		return render_amp( $attr );
	}
	return $content;
}

/**
 * Render slideshow block for AMP
 *
 * @param array $attr Array containing the slideshow block attributes.
 *
 * @return string
 */
function render_amp( $attr ) {
	if ( empty( $attr['ids'] ) ) {
		return '';
	}

	static $wp_block_jetpack_slideshow_id = 0;
	++$wp_block_jetpack_slideshow_id;

	$ids      = $attr['ids'];
	$autoplay = empty( $attr['autoplay'] ) ? false : true;
	$extras   = array(
		'wp-amp-block',
		$autoplay ? 'wp-block-jetpack-slideshow__autoplay' : null,
		$autoplay ? 'wp-block-jetpack-slideshow__autoplay-playing' : null,
	);
	$classes  = Blocks::classes( FEATURE_NAME, $attr, $extras );

	return sprintf(
		'<div class="%1$s" id="wp-block-jetpack-slideshow__%2$d"><div class="wp-block-jetpack-slideshow_container swiper-container">%3$s%4$s%5$s</div></div>',
		esc_attr( $classes ),
		absint( $wp_block_jetpack_slideshow_id ),
		amp_carousel( $attr, $wp_block_jetpack_slideshow_id ),
		$autoplay ? autoplay_ui( $wp_block_jetpack_slideshow_id ) : '',
		render_paginator( $ids, $wp_block_jetpack_slideshow_id )
	);
}

/**
 * Generate amp-carousel markup
 *
 * @param array $attr Array of block attributes.
 * @param int   $block_ordinal The ordinal number of the block, used in unique ID.
 *
 * @return string amp-carousel markup.
 */
function amp_carousel( $attr, $block_ordinal ) {
	$ids         = empty( $attr['ids'] ) ? array() : $attr['ids'];
	$first_image = wp_get_attachment_metadata( $ids[0] );
	$delay       = empty( $attr['delay'] ) ? 3 : absint( $attr['delay'] );
	$autoplay    = empty( $attr['autoplay'] ) ? false : $attr['autoplay'];
	$width       = empty( $first_image['width'] ) ? 800 : $first_image['width'];
	$height      = empty( $first_image['height'] ) ? 600 : $first_image['height'];
	return sprintf(
		'<amp-carousel width="%1$d" height="%2$d" layout="responsive" type="slides" data-next-button-aria-label="%3$s" data-prev-button-aria-label="%4$s" controls loop %5$s id="wp-block-jetpack-slideshow__amp-carousel__%6$s" on="slideChange:wp-block-jetpack-slideshow__amp-pagination__%6$s.toggle(index=event.index, value=true)">%7$s</amp-carousel>',
		esc_attr( $width ),
		esc_attr( $height ),
		esc_attr__( 'Next Slide', 'jetpack' ),
		esc_attr__( 'Previous Slide', 'jetpack' ),
		$autoplay ? 'autoplay delay=' . esc_attr( $delay * 1000 ) : '',
		absint( $block_ordinal ),
		implode( '', slides( $ids, $width, $height ) )
	);
}

/**
 * Generate array of slides markup
 *
 * @param array $ids Array of image ids.
 * @param int   $width Width of the container.
 * @param int   $height Height of the container.
 *
 * @return array Array of slides markup.
 */
function slides( $ids = array(), $width = 400, $height = 300 ) {
	return array_map(
		function ( $id ) use ( $width, $height ) {
			$caption    = wp_get_attachment_caption( $id );
			$figcaption = $caption ? sprintf(
				'<figcaption class="wp-block-jetpack-slideshow_caption gallery-caption">%s</figcaption>',
				wp_kses_post( $caption )
			) : '';
			$image      = wp_get_attachment_image(
				$id,
				array( $width, $height ),
				false,
				array(
					'class'      => 'wp-block-jetpack-slideshow_image',
					'object-fit' => 'contain',
				)
			);
			return sprintf(
				'<div class="wp-block-jetpack-slideshow_slide"><figure>%s%s</figure></div>',
				$image,
				$figcaption
			);
		},
		$ids
	);
}

/**
 * Render blocks paginator section
 *
 * @param array $ids Array of image ids.
 * @param int   $block_ordinal The ordinal number of the block, used in unique ID.
 *
 * @return array Array of bullets markup.
 */
function render_paginator( $ids = array(), $block_ordinal = 0 ) {
	$total = count( $ids );

	if ( $total < 6 ) {
		return bullets( $ids, $block_ordinal );
	}

	return sprintf(
		'<div class="swiper-pagination-simple">%s / %s</div>',
		absint( $block_ordinal ),
		absint( $total )
	);
}

/**
 * Generate array of bullets markup
 *
 * @param array $ids Array of image ids.
 * @param int   $block_ordinal The ordinal number of the block, used in unique ID.
 *
 * @return array Array of bullets markup.
 */
function bullets( $ids = array(), $block_ordinal = 0 ) {
	$buttons = array_map(
		function ( $index ) {
			$aria_label = sprintf(
				/* translators: %d: Slide number. */
				__( 'Go to slide %d', 'jetpack' ),
				absint( $index + 1 )
			);
			return sprintf(
				'<button option="%d" class="swiper-pagination-bullet" tabindex="0" role="button" aria-label="%s" %s></button>',
				absint( $index ),
				esc_attr( $aria_label ),
				0 === $index ? 'selected' : ''
			);
		},
		array_keys( $ids )
	);

	return sprintf(
		'<amp-selector id="wp-block-jetpack-slideshow__amp-pagination__%1$d" class="wp-block-jetpack-slideshow_pagination swiper-pagination swiper-pagination-custom amp-pagination" on="select:wp-block-jetpack-slideshow__amp-carousel__%1$d.goToSlide(index=event.targetOption)" layout="container">%2$s</amp-selector>',
		absint( $block_ordinal ),
		implode( '', $buttons )
	);
}

/**
 * Generate autoplay play/pause UI.
 *
 * @param int $block_ordinal The ordinal number of the block, used in unique ID.
 *
 * @return string Autoplay UI markup.
 */
function autoplay_ui( $block_ordinal = 0 ) {
	$block_id        = sprintf(
		'wp-block-jetpack-slideshow__%d',
		absint( $block_ordinal )
	);
	$amp_carousel_id = sprintf(
		'wp-block-jetpack-slideshow__amp-carousel__%d',
		absint( $block_ordinal )
	);
	$autoplay_pause  = sprintf(
		'<a aria-label="%s" class="wp-block-jetpack-slideshow_button-pause" role="button" on="tap:%s.toggleAutoplay(toggleOn=false),%s.toggleClass(class=wp-block-jetpack-slideshow__autoplay-playing,force=false)"></a>',
		esc_attr__( 'Pause Slideshow', 'jetpack' ),
		esc_attr( $amp_carousel_id ),
		esc_attr( $block_id )
	);
	$autoplay_play   = sprintf(
		'<a aria-label="%s" class="wp-block-jetpack-slideshow_button-play" role="button" on="tap:%s.toggleAutoplay(toggleOn=true),%s.toggleClass(class=wp-block-jetpack-slideshow__autoplay-playing,force=true)"></a>',
		esc_attr__( 'Play Slideshow', 'jetpack' ),
		esc_attr( $amp_carousel_id ),
		esc_attr( $block_id )
	);
	return $autoplay_pause . $autoplay_play;
}
