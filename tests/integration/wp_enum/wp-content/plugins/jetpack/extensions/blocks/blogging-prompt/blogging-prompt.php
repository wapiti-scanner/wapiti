<?php
/**
 * Blogging Prompt Block.
 *
 * @since 11.x
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Blogging_Prompt;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'blogging-prompt';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || \Jetpack::is_connection_ready() ) {
		Blocks::jetpack_register_block(
			BLOCK_NAME,
			array( 'render_callback' => __NAMESPACE__ . '\load_assets' )
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Blogging Prompt block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the Blogging Prompt block attributes.
 * @param string $content String containing the Blogging Prompt block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	/*
	 * Enqueue necessary scripts and styles.
	 */
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	return $content;
}
