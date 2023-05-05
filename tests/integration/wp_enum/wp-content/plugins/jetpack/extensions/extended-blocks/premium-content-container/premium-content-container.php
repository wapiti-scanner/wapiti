<?php
/**
 * Plan checks for uploading video files to premium-content/container.
 *
 * @package automattic/jetpack
 **/

// Populate the available extensions with premium-content/container.
add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				'premium-content/container',
			)
		);
	}
);

// Set the premium-content/container block availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_availability_for_plan( 'premium-content/container' );
	}
);
