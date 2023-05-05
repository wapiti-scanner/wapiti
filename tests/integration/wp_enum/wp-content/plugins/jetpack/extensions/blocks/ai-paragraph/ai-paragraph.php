<?php
/**
 * Jetpack AI Paragraph Block.
 *
 * @since 11.8
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\AIParagraph;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'ai-paragraph';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers our block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	if ( ! class_exists( 'Jetpack_AI_Helper' ) ) {
		require_once JETPACK__PLUGIN_DIR . '_inc/lib/class-jetpack-ai-helper.php';
	}

	if ( ! \Jetpack_AI_Helper::is_enabled() ) {
		return;
	}

	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\load_assets' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Jetpack AI Paragraph block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the Jetpack AI Paragraph block attributes.
 * @param string $content String containing the Jetpack AI Paragraph block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	/*
	 * Enqueue necessary scripts and styles.
	 */
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	return sprintf(
		'<div class="%1$s">%2$s</div>',
		esc_attr( Blocks::classes( FEATURE_NAME, $attr ) ),
		$content
	);
}
