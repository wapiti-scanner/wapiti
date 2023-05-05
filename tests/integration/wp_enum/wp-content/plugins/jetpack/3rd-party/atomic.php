<?php
/**
 * Helper functions for the Atomic platform.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Third_Party;

use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Status\Host;

/**
 * Handles suppressing development version notices on Atomic-hosted sites.
 *
 * @param bool $development_version Filterable value if this is a development version of Jetpack.
 *
 * @return bool
 */
function atomic_weekly_override( $development_version ) {
	if ( ( new Host() )->is_atomic_platform() ) {
		$haystack = Constants::get_constant( 'JETPACK__PLUGIN_DIR' );
		$needle   = '/jetpack-dev/';
		if (
			( function_exists( 'str_ends_with' ) && str_ends_with( $haystack, $needle ) ) || // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions.str_ends_withFound
			0 === substr_compare( $haystack, $needle, -13 )
		) {
			return $development_version; // Returns the default response if the active Jetpack version is from the beta plugin.
		}

		$development_version = false; // Returns false for regular installs on Atomic.
	}
	return $development_version; // Return default if not on Atomic.
}

add_filter( 'jetpack_development_version', __NAMESPACE__ . '\atomic_weekly_override' );
