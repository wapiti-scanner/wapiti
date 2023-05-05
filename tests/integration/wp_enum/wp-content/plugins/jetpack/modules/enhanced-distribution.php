<?php
/**
 * Module Name: Enhanced Distribution
 * Module Description: Increase reach and traffic.
 * Sort Order: 5
 * First Introduced: 1.2
 * Requires Connection: Yes
 * Auto Activate: Public
 * Module Tags: Writing
 * Feature: Engagement
 * Additional Search Queries: google, seo, firehose, search, broadcast, broadcasting
 *
 * @package automattic/jetpack
 */

/**
 * In case it's active prior to upgrading to '1.9'.
 */
function jetpack_enhanced_distribution_before_activate_default_modules() {
	$old_version         = Jetpack_Options::get_option( 'old_version' );
	list( $old_version ) = explode( ':', $old_version );

	if ( version_compare( $old_version, '1.9-something', '>=' ) ) {
		return;
	}

	Jetpack::check_privacy( __FILE__ );
}

add_action( 'jetpack_before_activate_default_modules', 'jetpack_enhanced_distribution_before_activate_default_modules' );

if ( isset( $_GET['get_freshly_pressed_data'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	/**
	 * If a request has ?get_freshly_pressed_data=true appended
	 * to the end, then let's provide the necessary data back via JSON.
	 */
	function jetpack_get_freshly_pressed_data() {
		if ( is_single() ) {
			wp_send_json_success(
				array(
					'blog_id' => Jetpack_Options::get_option( 'id' ),
					'post_id' => get_the_ID(),
				)
			);
		} else {
			wp_send_json_error(
				array(
					'message' => 'Not Singular',
				)
			);
		}
	}
	add_action( 'template_redirect', 'jetpack_get_freshly_pressed_data' );
}

add_action( 'rss_head', 'jetpack_enhanced_distribution_feed_id' );
add_action( 'rss_item', 'jetpack_enhanced_distribution_post_id' );
add_action( 'rss2_head', 'jetpack_enhanced_distribution_feed_id' );
add_action( 'rss2_item', 'jetpack_enhanced_distribution_post_id' );

/**
 * Output feed identifier based on blog ID.
 */
function jetpack_enhanced_distribution_feed_id() {
	$id = (int) Jetpack_Options::get_option( 'id' );
	if ( $id > 0 ) {
		$output = sprintf( '<site xmlns="com-wordpress:feed-additions:1">%d</site>', $id );
		echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}

/**
 * Output feed item identifier based on current post ID.
 */
function jetpack_enhanced_distribution_post_id() {
	$id = (int) get_the_ID();
	if ( $id ) {
		$output = sprintf( '<post-id xmlns="com-wordpress:feed-additions:1">%d</post-id>', $id );
		echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}
