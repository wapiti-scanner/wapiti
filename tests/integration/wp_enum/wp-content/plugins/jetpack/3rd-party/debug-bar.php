<?php
/**
 * 3rd Party integration for Debug Bar.
 *
 * @package automattic/jetpack
 */

/**
 * Checks if the search module is active, and if so, will initialize the singleton instance
 * of Jetpack_Search_Debug_Bar and add it to the array of debug bar panels.
 *
 * @param array $panels The array of debug bar panels.
 * @return array $panel The array of debug bar panels with our added panel.
 */
function init_jetpack_search_debug_bar( $panels ) {
	if ( ! Jetpack::is_module_active( 'search' ) ) {
		return $panels;
	}

	require_once __DIR__ . '/debug-bar/class-jetpack-search-debug-bar.php';
	$panels[] = Jetpack_Search_Debug_Bar::instance();
	return $panels;
}
add_filter( 'debug_bar_panels', 'init_jetpack_search_debug_bar' );
