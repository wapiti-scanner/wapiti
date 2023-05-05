<?php
/**
 * Payments plugin.
 *
 * @since 10.8
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Payments;

use Jetpack_Gutenberg;

const FEATURE_NAME = 'payments';

// Populate the available extensions with our feature.
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

// Set the feature availability, depending on the site plan.
add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		Jetpack_Gutenberg::set_availability_for_plan( FEATURE_NAME );
	}
);
