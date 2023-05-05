<?php
/**
 * Launchpad Save Modal
 *
 * @since 11.7
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\LaunchpadSaveModal;

// Feature name.
const FEATURE_NAME = 'launchpad-save-modal';

/**
 * Inject Launchpad options when in the block editor.
 */
function add_launchpad_options() {
	// Return early if we are not in the block editor.
	if ( ! wp_should_load_block_editor_scripts_and_styles() ) {
		return;
	}

	$launchpad_options = array(
		'launchpadScreenOption'       => get_option( 'launchpad_screen' ),
		'siteIntentOption'            => get_option( 'site_intent' ),
		'hasNeverPublishedPostOption' => get_option( 'has_never_published_post' ),
	);
	wp_add_inline_script(
		'jetpack-blocks-editor',
		'var Jetpack_LaunchpadSaveModal = ' . wp_json_encode( $launchpad_options, JSON_HEX_TAG | JSON_HEX_AMP ) . ';',
		'before'
	);
}
add_action( 'enqueue_block_assets', __NAMESPACE__ . '\add_launchpad_options' );

// Populate the available extensions with launchpad-save-modal.
add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				FEATURE_NAME,
			)
		);
	}
);

// Set the launchpad-save-modal availability.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_extension_available( FEATURE_NAME );
	}
);
