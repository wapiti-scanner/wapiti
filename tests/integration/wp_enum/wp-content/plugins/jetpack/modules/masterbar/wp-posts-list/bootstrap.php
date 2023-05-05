<?php
/**
 * WP-Admin Posts list bootstrap file.
 *
 * @package Jetpack
 */

/**
 * Load the Posts_List_Notification.
 */
function masterbar_init_wp_posts_list() {
	global $pagenow;

	if (
		( 'edit.php' === $pagenow && isset( $_GET['post_type'] ) && 'page' === $_GET['post_type'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	) {
		require_once __DIR__ . '/class-posts-list-page-notification.php';
		Automattic\Jetpack\Dashboard_Customizations\Posts_List_Page_Notification::init();
	}
}

add_action( 'init', 'masterbar_init_wp_posts_list', 1 );
