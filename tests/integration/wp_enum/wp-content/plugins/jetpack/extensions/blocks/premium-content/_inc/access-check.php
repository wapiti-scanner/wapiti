<?php
/**
 * Determine access to premium content.
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

use Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service\Token_Subscription_Service;

require_once __DIR__ . '/subscription-service/include.php';

/**
 * Determines if the memberships module is set up.
 *
 * @return bool Whether the memberships module is set up.
 */
function membership_checks() {
	// If Jetpack is not yet configured, don't show anything ...
	if ( ! class_exists( '\Jetpack_Memberships' ) ) {
		return false;
	}
	// if stripe not connected don't show anything...
	if ( empty( \Jetpack_Memberships::get_connected_account_id() ) ) {
		return false;
	}
	return true;
}

/**
 * Determines if the site has a plan that supports the
 * Premium Content block.
 *
 * @return bool
 */
function required_plan_checks() {
	$availability = \Jetpack_Gutenberg::get_cached_availability();
	$slug         = 'premium-content/container';
	return ( isset( $availability[ $slug ] ) && $availability[ $slug ]['available'] );
}

/**
 * Determines if the block should be rendered. Returns true
 * if the block passes all required checks, or if the user is
 * an editor.
 *
 * @return bool Whether the block should be rendered.
 */
function pre_render_checks() {
	return ( current_user_can_edit() || membership_checks() );
}

/**
 * Determines whether the current user can edit.
 *
 * @return bool Whether the user can edit.
 */
function current_user_can_edit() {
	$user = wp_get_current_user();

	return 0 !== $user->ID && current_user_can( 'edit_post', get_the_ID() );
}

/**
 * Determines if the current user can view the protected content of the given block.
 *
 * @param array  $attributes Block attributes.
 * @param object $block Block to check.
 *
 * @return bool Whether the use can view the content.
 */
function current_visitor_can_access( $attributes, $block ) {
	/**
	 * If the current WordPress install has as signed in user
	 * they can see the content.
	 */

	if ( current_user_can_edit() ) {
		return true;
	}

	$selected_plan_id = null;

	if ( isset( $attributes['selectedPlanId'] ) ) {
		$selected_plan_id = (int) $attributes['selectedPlanId'];
	}

	if ( isset( $block ) && isset( $block->context['premium-content/planId'] ) ) {
		$selected_plan_id = (int) $block->context['premium-content/planId'];
	}

	if ( empty( $selected_plan_id ) ) {
		return false;
	}

	$paywall      = subscription_service();
	$access_level = Token_Subscription_Service::POST_ACCESS_LEVEL_PAID_SUBSCRIBERS; // Only paid subscribers should be granted access to the premium content
	$can_view     = $paywall->visitor_can_view_content( array( $selected_plan_id ), $access_level );

	if ( $can_view ) {
		/**
		 * Fires when a visitor can view protected content on a site.
		 *
		 * @since 9.4.0
		 */
		do_action( 'jetpack_earn_remove_cache_headers' );
	}

	return $can_view;
}
