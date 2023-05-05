<?php
/**
 * Beaverbuilder Compatibility.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Third_Party;

add_action( 'init', __NAMESPACE__ . '\beaverbuilder_refresh' );

/**
 * If masterbar module is active force BeaverBuilder to refresh when publishing a layout.
 */
function beaverbuilder_refresh() {
	if ( \Jetpack::is_module_active( 'masterbar' ) ) {
		add_filter( 'fl_builder_should_refresh_on_publish', '__return_true' );
	}
}
