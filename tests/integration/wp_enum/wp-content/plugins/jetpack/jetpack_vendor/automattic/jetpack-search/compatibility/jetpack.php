<?php
/**
 * Jetpack compatibility
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search\Compatibility\Jetpack;

use Jetpack;

/**
 * Override the condition to show Search submenu when Jetpack plugin exists.
 */
function should_show_jetpack_search_submenu() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return false;
	}

	// If site is in Offline Mode or not connected yet.
	if ( ! Jetpack::is_active_and_not_offline_mode() ) {
		return false;
	}

	return true;
}

add_filter( 'jetpack_search_should_add_search_submenu', __NAMESPACE__ . '\should_show_jetpack_search_submenu' );
