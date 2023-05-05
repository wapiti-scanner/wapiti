<?php
/**
 * Module Name: Sitemaps
 * Module Description: Make it easy for search engines to find your site.
 * Sort Order: 13
 * First Introduced: 3.9
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Recommended, Traffic
 * Feature: Recommended
 * Additional Search Queries: sitemap, traffic, search, site map, seo
 *
 * @package automattic/jetpack
 */

/**
 * Disable direct access and execution.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( '1' == get_option( 'blog_public' ) ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
	include_once __DIR__ . '/sitemaps/sitemaps.php';

	// Disable WordPress 5.5-era sitemaps.
	add_filter( 'wp_sitemaps_enabled', '__return_false' );
}

add_action( 'jetpack_activate_module_sitemaps', 'jetpack_sitemap_on_activate' );

/**
 * Run when Sitemaps module is activated.
 *
 * @since 4.8.0
 */
function jetpack_sitemap_on_activate() {
	wp_clear_scheduled_hook( 'jp_sitemap_cron_hook' );
	require_once __DIR__ . '/sitemaps/sitemap-constants.php';
	require_once __DIR__ . '/sitemaps/sitemap-buffer.php';
	require_once __DIR__ . '/sitemaps/sitemap-stylist.php';
	require_once __DIR__ . '/sitemaps/sitemap-librarian.php';
	require_once __DIR__ . '/sitemaps/sitemap-finder.php';
	require_once __DIR__ . '/sitemaps/sitemap-builder.php';
}
