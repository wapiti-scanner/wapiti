<?php
/**
 * Payments Intro Block.
 *
 * Acts as a menu for select payments blocks
 *
 * @since 10.x
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\PaymentsIntro;

use Automattic\Jetpack\Blocks;

const FEATURE_NAME = 'payments-intro';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block( BLOCK_NAME );
}
add_action( 'init', __NAMESPACE__ . '\register_block' );
