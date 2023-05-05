<?php
/**
 * Premium Content Subscriber View Child Block.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Status\Host;
use Jetpack_Gutenberg;

const SUBSCRIBER_VIEW_NAME = 'premium-content/subscriber-view';

require_once dirname( __DIR__ ) . '/_inc/access-check.php';

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_subscriber_view_block() {
	// Only load this block on WordPress.com.
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || ( new Host() )->is_woa_site() ) {
		// Determine required `context` key based on Gutenberg version.
		$deprecated = function_exists( 'gutenberg_get_post_from_context' );
		$uses       = $deprecated ? 'context' : 'uses_context';

		Blocks::jetpack_register_block(
			SUBSCRIBER_VIEW_NAME,
			array(
				'render_callback' => __NAMESPACE__ . '\render_subscriber_view_block',
				$uses             => array( 'premium-content/planId' ),
			)
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_subscriber_view_block' );

/**
 * Render callback.
 *
 * @param array  $attributes Array containing the block attributes.
 * @param string $content    String containing the block content.
 * @param object $block      Object containing the full block.
 *
 * @return string
 */
function render_subscriber_view_block( $attributes, $content, $block = null ) {
	if ( ! pre_render_checks() ) {
		return '';
	}

	$visitor_has_access = current_visitor_can_access( $attributes, $block );

	if ( $visitor_has_access ) {
		Jetpack_Gutenberg::load_styles_as_required( SUBSCRIBER_VIEW_NAME );

		// The viewer has access to premium content, so the viewer can see the subscriber view content.
		return $content;
	}

	return '';
}
