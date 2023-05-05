<?php
/**
 * Plan checks for uploading audio files to core/audio.
 *
 * @package automattic/jetpack
 **/

// Populate the available extensions with core/audio.
add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				'core/audio',
			)
		);
	}
);

// Set the core/audio block availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_availability_for_plan( 'core/audio' );
	}
);
