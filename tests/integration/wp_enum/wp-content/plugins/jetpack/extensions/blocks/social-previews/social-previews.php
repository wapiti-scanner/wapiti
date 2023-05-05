<?php
/**
 * Social Previews Block.
 *
 * @since 8.x
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Social_Previews;

use Automattic\Jetpack\Blocks;

const FEATURE_NAME = 'social-previews';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the Social Previews feature with the block editor.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'plan_check' => false,
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );
