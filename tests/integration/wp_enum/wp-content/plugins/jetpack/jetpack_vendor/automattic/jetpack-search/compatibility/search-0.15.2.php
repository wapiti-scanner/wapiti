<?php
/**
 * Compatibility for Jetpack Search version <= 0.15.2.
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search\Compatibility\Jetpack;

use Automattic\Jetpack\Search\Instant_Search;

add_filter( 'option_sidebars_widgets', __NAMESPACE__ . '\convert_old_jetpack_search_sidebar', 10, 2 );

/**
 * Map the old Jetpack Search sidebar to the new Instant Search sidebar.
 *
 * @param array $sidebars_widgets Value of `sidebars_widgets` option.
 */
function convert_old_jetpack_search_sidebar( $sidebars_widgets ) {
	if ( ! empty( $sidebars_widgets[ Instant_Search::INSTANT_SEARCH_SIDEBAR ] ) || empty( $sidebars_widgets[ Instant_Search::OLD_INSTANT_SEARCH_SIDEBAR ] ) ) {
		return $sidebars_widgets;
	}
	$sidebars_widgets[ Instant_Search::INSTANT_SEARCH_SIDEBAR ] = $sidebars_widgets[ Instant_Search::OLD_INSTANT_SEARCH_SIDEBAR ];
	unset( $sidebars_widgets[ Instant_Search::OLD_INSTANT_SEARCH_SIDEBAR ] );
	return $sidebars_widgets;
}
