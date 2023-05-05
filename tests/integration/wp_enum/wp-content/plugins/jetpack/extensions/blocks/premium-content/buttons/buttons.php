<?php
/**
 * Premium Content Buttons Child Block.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Status\Host;
use Jetpack_Gutenberg;

const BUTTONS_NAME = 'premium-content/buttons';

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_buttons_block() {
	// Only load this block on WordPress.com.
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || ( new Host() )->is_woa_site() ) {
		Blocks::jetpack_register_block(
			BUTTONS_NAME,
			array(
				'render_callback' => __NAMESPACE__ . '\render_buttons_block',
			)
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_buttons_block' );

/**
 * Render callback.
 *
 * @param array  $attributes Array containing the block attributes.
 * @param string $content    String containing the block content.
 *
 * @return string
 */
function render_buttons_block( $attributes, $content ) {
	Jetpack_Gutenberg::load_styles_as_required( BUTTONS_NAME );

	return $content;
}
