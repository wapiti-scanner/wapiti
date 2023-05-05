<?php
/**
 * VideoPress Block.
 *
 * @since 11.1.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\VideoPress;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME   = 'videopress-block';
const FEATURE_FOLDER = 'videopress';
const BLOCK_NAME     = 'jetpack/' . FEATURE_NAME;

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
 * VideoPress block registration/dependency declaration.
 *
 * @param array  $attrs   Array containing the VideoPress block attributes.
 * @param string $content String containing the VideoPress block content.
 *
 * @return string
 */
function load_assets( $attrs, $content ) {
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_FOLDER );
	return $content;
}
