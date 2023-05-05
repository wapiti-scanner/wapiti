<?php
/**
 * Another helper class for parsing Jetpack Search options.
 *
 * @package    automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Constants;

/**
 * Helpers for parsing the various Search options
 */
class Options {
	/**
	 * The search widget's base ID.
	 *
	 * @since 5.8.0
	 * @var string
	 */
	const FILTER_WIDGET_BASE = 'jetpack-search-filters';

	/**
	 * Prefix for options in DB.
	 *
	 * @since 8.3.0
	 * @var string
	 */
	const OPTION_PREFIX = 'jetpack_search_';

	/**
	 * Available result formats.
	 *
	 * @since 9.6.0
	 * @var string
	 */
	const RESULT_FORMAT_MINIMAL  = 'minimal';
	const RESULT_FORMAT_EXPANDED = 'expanded';
	const RESULT_FORMAT_PRODUCT  = 'product';

	/**
	 * Available overlay triggers.
	 *
	 * @since 9.9.0
	 * @var string
	 */
	const OVERLAY_TRIGGER_IMMEDIATE = 'immediate';
	const OVERLAY_TRIGGER_SUBMIT    = 'submit';
	const DEFAULT_OVERLAY_TRIGGER   = self::OVERLAY_TRIGGER_SUBMIT;

	/**
	 * Deprecated overlay trigger.
	 *
	 * @var string
	 * @deprecated since 11.3
	 */
	const OVERLAY_TRIGGER_RESULTS = 'results';

	/**
	 * Returns a boolean for whether instant search is enabled.
	 *
	 * @since 8.3.0
	 *
	 * @return bool
	 */
	public static function is_instant_enabled() {
		return true === (bool) get_option( 'instant_search_enabled' );
	}

	/**
	 * Returns a boolean for whether the current site has a VIP index.
	 *
	 * @since 5.8.0
	 *
	 * @return bool
	 */
	public static function site_has_vip_index() {
		$has_vip_index = (
			Constants::is_defined( 'JETPACK_SEARCH_VIP_INDEX' ) &&
			Constants::get_constant( 'JETPACK_SEARCH_VIP_INDEX' )
		);

		/**
		 * Allows developers to filter whether the current site has a VIP index.
		 *
		 * @module search
		 *
		 * @since  5.8.0
		 *
		 * @param bool $has_vip_index Whether the current site has a VIP index.
		 */
		return apply_filters( 'jetpack_search_has_vip_index', $has_vip_index );
	}

}
