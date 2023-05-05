<?php
/**
 * Plan checks for uploading video files to core/cover.
 *
 * @package automattic/jetpack
 **/

// Populate the available extensions with core/cover.
add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				'core/cover',
			)
		);
	}
);

// Set the core/cover block availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_availability_for_plan( 'core/cover' );
	}
);
