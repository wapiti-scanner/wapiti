<?php
/**
 * Module Name: SEO Tools
 * Module Description: Better results on search engines and social media.
 * Sort Order: 35
 * Recommendation Order: 15
 * First Introduced: 4.4
 * Requires Connection: Yes
 * Requires User Connection: No
 * Auto Activate: No
 * Module Tags: Social, Appearance
 * Feature: Traffic
 * Additional Search Queries: search engine optimization, social preview, meta description, custom title format
 *
 * @package automattic/jetpack
 */

// Suppress SEO Tools output if any of the following plugins is active.
$jetpack_seo_conflicting_plugins = array(
	'wordpress-seo/wp-seo.php',
	'wordpress-seo-premium/wp-seo-premium.php',
	'all-in-one-seo-pack/all_in_one_seo_pack.php',
	'all-in-one-seo-pack-pro/all_in_one_seo_pack.php',
	'seo-by-rank-math/rank-math.php',
	'autodescription/autodescription.php',
	'slim-seo/slim-seo.php',
	'wp-seopress/seopress.php',
	'wp-seopress-pro/seopress-pro.php',
	'seo-key/seo-key.php',
	'seo-key-pro/seo-key.php',
);

foreach ( $jetpack_seo_conflicting_plugins as $seo_plugin ) {
	if ( Jetpack::is_plugin_active( $seo_plugin ) ) {
		// Disable all custom meta tags that SEO tools manages.
		add_filter( 'jetpack_disable_seo_tools', '__return_true' );

		// Also disable default meta tags.
		add_filter( 'jetpack_seo_meta_tags_enabled', '__return_false' );
		break;
	}
}

/** This filter is documented in modules/seo-tools/class-jetpack-seo-utils.php */
if ( ! apply_filters( 'jetpack_disable_seo_tools', false ) ) {
	require_once __DIR__ . '/seo-tools/class-jetpack-seo.php';
	new Jetpack_SEO();
}
