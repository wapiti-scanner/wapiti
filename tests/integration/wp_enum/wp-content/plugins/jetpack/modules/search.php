<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Search
 * Module Description: Help visitors quickly find answers with highly relevant instant search results and powerful filtering.
 * First Introduced: 5.0
 * Sort Order: 34
 * Free: false
 * Requires Connection: Yes
 * Auto Activate: No
 * Feature: Search
 * Additional Search Queries: search, elastic, elastic search, elasticsearch, fast search, search results, search performance, google search
 * Plans: business, complete
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Search\Classic_Search;
use Automattic\Jetpack\Search\Helper as Search_Helper;

/**
 * These are old legacy class names that were deprecated due to the move to packages.
 *
 * @todo Does this make more sense as a legacy dir in the search package?
 */

/**
 * Jetpack Search deprecated class.
 *
 * @deprecated 10.6
 */
class Jetpack_Search {
	/**
	 * Singleton
	 */
	protected function __construct() {
	}

	/**
	 * Return the instance of the new class.
	 */
	public static function instance() {
		// Explicitly provide the blog ID, just in case.
		return Classic_Search::instance( Search_Helper::get_wpcom_site_id() );
	}
}
