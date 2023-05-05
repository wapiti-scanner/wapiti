<?php
/**
 * Revue Block.
 *
 * @since 8.3.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Revue;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'revue';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

// @TODO Due to Revue being shut down as of 18th Jan 2023, this whole block should be removed a couple of months later.
/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\render_block' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Revue block render callback.
 *
 * @param array $attributes Array containing the Revue block attributes.
 *
 * @return string
 */
function render_block( $attributes ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	if ( current_user_can( 'manage_options' ) ) {
		$message  = esc_html__( 'Revue is shutting down. The Revue signup form will no longer be displayed to your visitors and as such this block should be removed.', 'jetpack' );
		$message .= '<br/><br/>';
		$message .= sprintf(
			' <a href="%1$s" target="_blank" rel="noopener noreferrer">%2$s</a>',
			esc_url( 'https://wordpress.com/go/digital-marketing/migrate-from-revue-newsletter/' ),
			esc_html__( 'You can migrate from Revue to the WordPress.com Newsletter - find out more here.', 'jetpack' )
		);

		return Jetpack_Gutenberg::notice(
			$message,
			'warning',
			Blocks::classes( FEATURE_NAME, $attributes )
		);
	}
}
