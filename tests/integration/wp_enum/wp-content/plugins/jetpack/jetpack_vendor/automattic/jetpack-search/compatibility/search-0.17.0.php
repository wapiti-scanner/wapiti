<?php
/**
 * Compatibility for Jetpack Search version <= 0.17.0.
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search\Compatibility\Jetpack;

add_filter( 'option_jetpack_search_overlay_trigger', __NAMESPACE__ . '\map_results_overlay_trigger', 10, 2 );

/**
 * We've retired the 'results' overlay trigger and want to migrate users to the similar 'immediate' setting.
 *
 * @param string $overlay_trigger Overlay trigger.
 */
function map_results_overlay_trigger( $overlay_trigger ) {
	return 'results' === $overlay_trigger ? \Automattic\Jetpack\Search\Options::OVERLAY_TRIGGER_IMMEDIATE : $overlay_trigger;
}
