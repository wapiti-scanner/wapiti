<?php
/**
 * Module Name: WooCommerce Analytics
 * Module Description: Enhanced analytics for WooCommerce and Jetpack users.
 * Sort Order: 13
 * First Introduced: 8.4
 * Requires Connection: Yes
 * Auto Activate: Yes
 * Module Tags: Other, Recommended
 * Feature: Engagement
 * Additional Search Queries: woocommerce, analytics, stats, statistics, tracking, analytics, views
 *
 * @package automattic/jetpack
 */

/**
 * Load module functionality.
 */
function jetpack_load_woocommerce_analytics() {
	require_once __DIR__ . '/woocommerce-analytics/class-jetpack-woocommerce-analytics.php';
}
jetpack_load_woocommerce_analytics();
