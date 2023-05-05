<?php
/**
 * Plan checks for uploading video files to core/video.
 *
 * @package automattic/jetpack
 **/

// Populate the available extensions with core/video.
add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				'core/video',
			)
		);
	}
);

// Set the core/video block availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_availability_for_plan( 'core/video' );
	}
);
