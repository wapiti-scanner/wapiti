<?php
/**
 * The Default Filter Settings class.
 *
 * This class provides the default whitelist values for the Sync data filters.
 * See the DATA_FILTER_DEFAULTS constant for the list of filters.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * The Default_Filter_Settings class
 */
class Default_Filter_Settings {

	/**
	 * The class that contains the default values of the filters.
	 */
	const DEFAULT_FILTER_CLASS = 'Automattic\Jetpack\Sync\Defaults';

	/**
	 * A map of each Sync filter name to the associated property name in the Defaults class.
	 */
	const DATA_FILTER_DEFAULTS = array(
		'jetpack_sync_options_whitelist'            => 'default_options_whitelist',
		'jetpack_sync_options_contentless'          => 'default_options_contentless',
		'jetpack_sync_constants_whitelist'          => 'default_constants_whitelist',
		'jetpack_sync_callable_whitelist'           => 'default_callable_whitelist',
		'jetpack_sync_multisite_callable_whitelist' => 'default_multisite_callable_whitelist',
		'jetpack_sync_post_meta_whitelist'          => 'post_meta_whitelist',
		'jetpack_sync_comment_meta_whitelist'       => 'comment_meta_whitelist',
		'jetpack_sync_capabilities_whitelist'       => 'default_capabilities_whitelist',
		'jetpack_sync_known_importers'              => 'default_known_importers',
	);

	/**
	 * The data associated with these filters are stored as associative arrays.
	 * (All other filters store data as indexed arrays.)
	 */
	const ASSOCIATIVE_FILTERS = array(
		'jetpack_sync_callable_whitelist',
		'jetpack_sync_multisite_callable_whitelist',
		'jetpack_sync_known_importers',
	);

	/**
	 * Returns the default data settings list for the provided filter.
	 *
	 * @param string $filter The filter name.
	 *
	 * @return array|false The default list of data settings. Returns false if the provided
	 *                     filter doesn't not have an array of default settings.
	 */
	public function get_default_settings( $filter ) {
		if ( ! is_string( $filter ) || ! array_key_exists( $filter, self::DATA_FILTER_DEFAULTS ) ) {
			return false;
		}

		$property = self::DATA_FILTER_DEFAULTS[ $filter ];
		$class    = self::DEFAULT_FILTER_CLASS;
		return $class::$$property;
	}

	/**
	 * Returns an array containing the default values for all of the filters shown
	 * in DATA_FILTER_DEFAULTS.
	 *
	 * @return array The array containing all sync data filters and their default values.
	 */
	public function get_all_filters_default_settings() {
		$defaults = array();

		foreach ( self::DATA_FILTER_DEFAULTS as $filter => $default_location ) {
			$defaults[ $filter ] = $this->get_default_settings( $filter );
		}
		return $defaults;
	}
}
